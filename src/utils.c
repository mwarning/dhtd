
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <limits.h>

#include "main.h"
#include "log.h"
#include "conf.h"
#include "utils.h"


// separate a string into a list of arguments (int argc, char **argv)
int setargs(const char **argv, int argv_size, char *args)
{
    int count = 0;

    // skip spaces
    while (isspace(*args)) {
        ++args;
    }

    while (*args) {
        if ((count + 1) < argv_size) {
            argv[count] = args;
        } else {
            log_error("CLI: too many arguments");
            break;
        }

        // parse word
        while (*args && !isspace(*args)) {
            ++args;
        }

        if (*args) {
            *args++ = '\0';
        }

        // skip spaces
        while (isspace(*args)) {
            ++args;
        }

        count++;
    }

    argv[MIN(count, argv_size - 1)] = NULL;

    return count;
}

bool parse_id(uint8_t id[], size_t idsize, const char query[], size_t querysize)
{
    if (bytes_from_base16(id, idsize, query, querysize)) {
        return true;
    }

    return false;
}

bool is_id(const char query[])
{
    uint8_t id[SHA1_BIN_LENGTH];
    return parse_id(id, sizeof(id), query, strlen(query));
}

// "<hex-id>[:<port>]"
bool parse_annoucement(uint8_t id[], int *port, const char query[], int default_port)
{
    const char *beg = query;
    const char *colon = strchr(beg, ':');
    size_t len = strlen(query);

    if (colon) {
        int n = parse_int(colon + 1, -1);
        if (!port_valid(n)) {
            return false;
        }
        *port = n;
        len = colon - beg;
    } else {
        *port = default_port;
    }

    return parse_id(id, SHA1_BIN_LENGTH, query, len);
}

// "<hex-id>[:<port>]"
bool is_announcement(const char query[])
{
    uint8_t id[SHA1_BIN_LENGTH];
    int port;
    return parse_annoucement(id, &port, query, -1);
}

static size_t base16_len(size_t len)
{
    return 2 * len;
}

bool bytes_from_base16(uint8_t dst[], size_t dstsize, const char src[], size_t srcsize)
{
    size_t i;
    size_t xv = 0;

    if (base16_len(dstsize) != srcsize) {
        return false;
    }

    for (i = 0; i < srcsize; ++i) {
        const char c = src[i];
        if (c >= '0' && c <= '9') {
            xv += c - '0';
        } else if (c >= 'a' && c <= 'f') {
            xv += (c - 'a') + 10;
        } else if (c >= 'A' && c <= 'F') {
            xv += (c - 'A') + 10;
        } else {
            return false;
        }

        if (i % 2) {
            dst[i / 2] = xv;
            xv = 0;
        } else {
            xv *= 16;
        }
    }

    return true;
}

char *bytes_to_base16(char dst[], size_t dstsize, const uint8_t src[], size_t srcsize)
{
    static const char hexchars[16] = "0123456789abcdef";

    // + 1 for the '\0'
    if (dstsize != (base16_len(srcsize) + 1)) {
        return NULL;
    }

    for (size_t i = 0; i < srcsize; ++i) {
        dst[2 * i] = hexchars[src[i] / 16];
        dst[2 * i + 1] = hexchars[src[i] % 16];
    }

    dst[2 * srcsize] = '\0';

    return dst;
}

/*
* Sanitize a query string.
* Convert to lowercase.
*/
int query_sanitize(char buf[], size_t buflen, const char query[])
{
    size_t len = strlen(query);

    if ((len + 1) > buflen) {
        // Output buffer too small
        return EXIT_FAILURE;
    }

    // Convert to lower case
    for (size_t i = 0; i <= len; ++i) {
        buf[i] = tolower(query[i]);
    }

    return EXIT_SUCCESS;
}


const option_t *find_option(const option_t options[], const char name[])
{
    const option_t *option = options;
    while (option->name && name) {
        if (0 == strcmp(name, option->name)) {
            return option;
        }
        option++;
    }

    return NULL;
}

// Create a random port != 0
int port_random(void)
{
    uint16_t port;

    do {
        bytes_random((uint8_t*) &port, sizeof(port));
    } while (port == 0);

    return port;
}

bool port_valid(int port)
{
    return port > 0 && port <= 65536;
}

int parse_int(const char *s, int err)
{
    char *endptr = NULL;
    const char *end = s + strlen(s);
    ssize_t n = strtoul(s, &endptr, 10);
    if (endptr != s && endptr == end && n >= INT_MIN && n < INT_MAX) {
        return n;
    } else {
        return err;
    }
}

bool port_set(IP *addr, uint16_t port)
{
    switch (addr->ss_family) {
    case AF_INET:
        ((IP4 *)addr)->sin_port = htons(port);
        return true;
    case AF_INET6:
        ((IP6 *)addr)->sin6_port = htons(port);
        return true;
    default:
        return false;
    }
}

// Fill buffer with random bytes
int bytes_random(uint8_t buffer[], size_t size)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        log_error("Failed to open /dev/urandom");
        exit(1);
    }

    int rc = read(fd, buffer, size);

    close(fd);

    return rc;
}

bool id_equal(const uint8_t id1[], const uint8_t id2[])
{
    return (memcmp(id1, id2, SHA1_BIN_LENGTH) == 0);
}

const char *str_id(const uint8_t id[])
{
    static char hexbuf[2 * SHA1_BIN_LENGTH + 1];
    return bytes_to_base16(hexbuf, sizeof(hexbuf), id, SHA1_BIN_LENGTH);
}

const char *str_af(int af) {
    switch (af) {
    case AF_INET:
        return "IPv4";
    case AF_INET6:
        return "IPv6";
    case AF_UNSPEC:
        return "IPv4+IPv6";
    default:
        return "<invalid>";
    }
}

const char *str_addr2(const void *ip, uint8_t length, uint16_t port)
{
    static char addrbuf[FULL_ADDSTRLEN];
    char buf[INET6_ADDRSTRLEN];
    const char *fmt;

    switch (length) {
    case 16:
        inet_ntop(AF_INET6, ip, buf, sizeof(buf));
        fmt = "[%s]:%d";
        break;
    case 4:
        inet_ntop(AF_INET, ip, buf, sizeof(buf));
        fmt = "%s:%d";
        break;
    default:
        return "<invalid address>";
    }

    sprintf(addrbuf, fmt, buf, port);

    return addrbuf;
}

const char *str_addr(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET6: {
        uint16_t port = ntohs(((IP6 *)addr)->sin6_port);
        return str_addr2(&((IP6 *)addr)->sin6_addr, 16, port);
    }
    case AF_INET: {
        uint16_t port = ntohs(((IP4 *)addr)->sin_port);
        return str_addr2(&((IP4 *)addr)->sin_addr, 4, port);
    }
    default:
        return "<invalid address>";
    }
}

bool addr_is_localhost(const IP *addr)
{
    // 127.0.0.1
    const uint32_t inaddr_loopback = htonl(INADDR_LOOPBACK);

    switch (addr->ss_family) {
    case AF_INET:
        return (memcmp(&((IP4 *)addr)->sin_addr, &inaddr_loopback, 4) == 0);
    case AF_INET6:
        return (memcmp(&((IP6 *)addr)->sin6_addr, &in6addr_loopback, 16) == 0);
    default:
        return false;
    }
}

bool addr_is_multicast(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return IN_MULTICAST(ntohl(((IP4*) addr)->sin_addr.s_addr));
    case AF_INET6:
        return IN6_IS_ADDR_MULTICAST(&((IP6*) addr)->sin6_addr);
    default:
        return false;
    }
}

int addr_port(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return ntohs(((IP4 *)addr)->sin_port);
    case AF_INET6:
        return ntohs(((IP6 *)addr)->sin6_port);
    default:
        return 0;
    }
}

int addr_len(const IP *addr)
{
    switch (addr->ss_family) {
    case AF_INET:
        return sizeof(IP4);
    case AF_INET6:
        return sizeof(IP6);
    default:
        return 0;
    }
}

const char *str_bytes(uint64_t bytes)
{
    static char strbytesbuf[4][8];
    static size_t strbytesbuf_i = 0;
    char *buf = strbytesbuf[++strbytesbuf_i % 4];

    if (bytes < 1000) {
        snprintf(buf, 8, "%u B", (unsigned) bytes);
    } else if (bytes < 1000000) {
        snprintf(buf, 8, "%.1f K", bytes / 1000.0);
    } else if (bytes < 1000000000) {
        snprintf(buf, 8, "%.1f M", bytes / 1000000.0);
    } else if (bytes < 1000000000000) {
        snprintf(buf, 8, "%.1f G", bytes / 1000000000.0);
    } else if (bytes < 1000000000000000) {
        snprintf(buf, 8, "%.1f T", bytes / 1000000000000.0);
    } else if (bytes < 1000000000000000000) {
        snprintf(buf, 8, "%.1f P", bytes / 1000000000000000.0);
    } else {
        snprintf(buf, 8, "%.1f E", bytes / 1000000000000000000.0);
    }

    return buf;
}

const char *str_time(time_t time)
{
    static char strdurationbuf[4][64];
    static size_t strdurationbuf_i = 0;
    char *buf = strdurationbuf[++strdurationbuf_i % 4];

    size_t years, days, hours, minutes, seconds;
    const char *prefix = "";

    if (time < 0) {
        time = -time;
        // prepend minus sign
        prefix = "-";
    }

    years = time / (365 * 24 * 60 * 60);
    time -= years * (365 * 24 * 60 * 60);
    days = time / (24 * 60 * 60);
    time -= days * (24 * 60 * 60);
    hours = time / (60 * 60);
    time -= hours * (60 * 60);
    minutes = time / 60;
    time -= minutes * 60;
    seconds = time;

    if (years > 0) {
        snprintf(buf, 64, "%s%zuy%zud", prefix, years, days);
    } else if (days > 0) {
        snprintf(buf, 64, "%s%zud%zuh", prefix, days, hours);
    } else if (hours > 0) {
        snprintf(buf, 64, "%s%zuh%zum", prefix, hours, minutes);
    } else if (minutes > 0) {
        snprintf(buf, 64, "%s%zum%zus", prefix, minutes, seconds);
    } else {
        snprintf(buf, 64, "%s%zus", prefix, seconds);
    }

    return buf;
}

static bool addr_parse_internal(IP *ret, const char addr_str[], const char port_str[], int af)
{
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct addrinfo *p = NULL;
    bool rc = false;

    memset(&hints, '\0', sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = af;

    if (getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
        return false;
    }

    p = info;
    while (p != NULL) {
        if ((af == AF_UNSPEC || af == AF_INET6) && p->ai_family == AF_INET6) {
            memcpy(ret, p->ai_addr, sizeof(IP6));
            rc = true;
            break;
        }

        if ((af == AF_UNSPEC || af == AF_INET) && p->ai_family == AF_INET) {
            memcpy(ret, p->ai_addr, sizeof(IP4));
            rc = true;
            break;
        }
        p = p->ai_next;
    }

    freeaddrinfo(info);

    return rc;
}

/*
* Parse/Resolve various string representations of
* IPv4/IPv6 addresses and optional port.
* An address can also be a domain name.
* A port can also be a service	(e.g. 'www').
*
* "<address>"
* "<ipv4_address>:<port>"
* "[<address>]"
* "[<address>]:<port>"
*/
bool addr_parse(IP *addr_ret, const char full_addr_str[], const char default_port[], int af)
{
    char addr_buf[256];
    char *addr_beg;
    char *addr_tmp;
    char *last_colon;
    const char *addr_str = NULL;
    const char *port_str = NULL;
    size_t len;

    len = strlen(full_addr_str);
    if (len >= (sizeof(addr_buf) - 1)) {
        // address too long
        return false;
    } else {
        addr_beg = addr_buf;
    }

    memset(addr_buf, '\0', sizeof(addr_buf));
    memcpy(addr_buf, full_addr_str, len);

    last_colon = strrchr(addr_buf, ':');

    if (addr_beg[0] == '[') {
        // [<addr>] or [<addr>]:<port>
        addr_tmp = strrchr(addr_beg, ']');

        if (addr_tmp == NULL) {
            // broken format
            return false;
        }

        *addr_tmp = '\0';
        addr_str = addr_beg + 1;

        if (*(addr_tmp + 1) == '\0') {
            port_str = default_port;
        } else if (*(addr_tmp + 1) == ':') {
            port_str = addr_tmp + 2;
        } else {
            // port expected
            return false;
        }
    } else if (last_colon && last_colon == strchr(addr_buf, ':')) {
        // <non-ipv6-addr>:<port>
        addr_tmp = last_colon;
        *addr_tmp = '\0';
        addr_str = addr_buf;
        port_str = addr_tmp + 1;
    } else {
        // <addr>
        addr_str = addr_buf;
        port_str = default_port;
    }

    return addr_parse_internal(addr_ret, addr_str, port_str, af);
}

// Compare two ip addresses, ignore port
bool addr_equal(const IP *addr1, const IP *addr2)
{
    if (addr1->ss_family != addr2->ss_family) {
        return 0;
    } else if (addr1->ss_family == AF_INET) {
        return 0 == memcmp(&((IP4 *)addr1)->sin_addr, &((IP4 *)addr2)->sin_addr, 4);
    } else if (addr1->ss_family == AF_INET6) {
        return 0 == memcmp(&((IP6 *)addr1)->sin6_addr, &((IP6 *)addr2)->sin6_addr, 16);
    } else {
        return false;
    }
}

bool socket_addr(int sock, IP *addr)
{
    socklen_t len = sizeof(IP);
    return getsockname(sock, (struct sockaddr *) addr, &len) == 0;
}

time_t time_add_secs(uint32_t seconds)
{
    return gconf->time_now + seconds;
}

time_t time_add_mins(uint32_t minutes)
{
    return gconf->time_now + (60 * minutes);
}

time_t time_add_hours(uint32_t hours)
{
    return gconf->time_now + (60 * 60 * hours);
}
