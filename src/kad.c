
#define _GNU_SOURCE

#include <sys/time.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"
#include "main.h"
#include "utils.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "announces.h"
#include "results.h"

// include dht.c instead of dht.h to access private vars
#include "dht.c"


/*
* The interface that is used to interact with the DHT.
*/

// Next time to do DHT maintenance
static time_t g_dht_maintenance = 0;
static int g_dht_socket4 = -1;
static int g_dht_socket6 = -1;

// This callback is called when a search result arrives or a search completes
void dht_callback_func(void *closure, int event, const uint8_t *info_hash, const void *data, size_t data_len)
{
    switch (event) {
        case DHT_EVENT_VALUES:
            results_add(info_hash, AF_INET, data, data_len);
            break;
        case DHT_EVENT_VALUES6:
            results_add(info_hash, AF_INET6, data, data_len);
            break;
        case DHT_EVENT_SEARCH_DONE:
        case DHT_EVENT_SEARCH_DONE6:
            break;
        case DHT_EVENT_SEARCH_EXPIRED:
            results_clear(info_hash);
            break;
    }
}

static void clear_old_traffic_counters()
{
    size_t idx = gconf->time_now % TRAFFIC_DURATION_SECONDS;
    uint32_t since = (gconf->time_now - gconf->traffic_time);
    size_t n = MIN(since, TRAFFIC_DURATION_SECONDS);

    // clear old traffic measurement buckets
    for (size_t i = 0; i < n; ++i) {
        size_t j = (TRAFFIC_DURATION_SECONDS + idx + i + 1) % TRAFFIC_DURATION_SECONDS;
        gconf->traffic_in[j] = 0;
        gconf->traffic_out[j] = 0;
    }
}

static void record_traffic(uint32_t in_bytes, uint32_t out_bytes)
{
    clear_old_traffic_counters();

    gconf->traffic_in_sum += in_bytes;
    gconf->traffic_out_sum += out_bytes;

    size_t idx = gconf->time_now % TRAFFIC_DURATION_SECONDS;
    gconf->traffic_time = gconf->time_now;
    gconf->traffic_in[idx] += out_bytes;
    gconf->traffic_out[idx] += in_bytes;
}

// Handle incoming packets and pass them to the DHT code
void dht_handler(int rc, int sock)
{
    uint8_t buf[1500];
    ssize_t buflen = 0;
    IP from;

    if (rc > 0) {
        // Check which socket received the data
        socklen_t fromlen = sizeof(from);
        buflen = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen);

        if (buflen <= 0 || buflen >= sizeof(buf)) {
            return;
        }

        record_traffic(buflen, 0);

        // The DHT code expects the message to be null-terminated.
        buf[buflen] = '\0';
    }

    if (buflen > 0) {
        // Handle incoming data
        time_t time_wait = 0;
        socklen_t fromlen = sizeof(from);
        rc = dht_periodic(buf, buflen, (struct sockaddr*) &from, fromlen, &time_wait, dht_callback_func, NULL);

        if (rc < 0 && errno != EINTR) {
            if (rc == EINVAL || rc == EFAULT) {
                log_error("KAD: Error calling dht_periodic");
                exit(1);
            }
            g_dht_maintenance = time_now_sec() + 1;
        } else {
            g_dht_maintenance = time_now_sec() + time_wait;
        }
    } else if (g_dht_maintenance <= time_now_sec()) {
        // Do a maintenance call
        time_t time_wait = 0;
        rc = dht_periodic(NULL, 0, NULL, 0, &time_wait, dht_callback_func, NULL);

        // Wait for the next maintenance call
        g_dht_maintenance = time_now_sec() + time_wait;
        //log_debug("KAD: Next maintenance call in %u seconds.", (unsigned) time_wait);
    } else {
        rc = 0;
    }

    if (rc < 0) {
        if (errno == EINTR) {
            return;
        } else if (rc == EINVAL || rc == EFAULT) {
            log_error("KAD: Error using select: %s", strerror(errno));
            return;
        } else {
            g_dht_maintenance = time_now_sec() + 1;
        }
    }
}

/*
* Kademlia needs dht_blacklisted/dht_hash/dht_random_bytes functions to be present.
*/

int dht_sendto(int sockfd, const void *buf, int buflen, int flags, const struct sockaddr *to, int tolen)
{
    record_traffic(0, buflen);

    return sendto(sockfd, buf, buflen, flags, to, tolen);
}

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
    return 0;
}

// Hashing for the DHT - implementation does not matter for interoperability
void dht_hash(void *hash_return, int hash_size,
        const void *v1, int len1,
        const void *v2, int len2,
        const void *v3, int len3)
{
    union {
        uint8_t data[8];
        uint16_t num4[4];
        uint32_t num2[2];
        uint64_t num1[1];
    } hash;

    assert(len1 == 8);
    memcpy(&hash.data, v1, 8);

    assert(len2 == 4 || len2 == 16);
    if (len2 == 4) {
        const uint32_t d2 = *((uint32_t*) v2);
        hash.num2[0] ^= d2;
        hash.num2[1] ^= d2;
    } else {
        hash.num1[0] ^= *((uint64_t*) v2);
        hash.num1[0] ^= *((uint64_t*) v2 + 8);
    }

    assert(len3 == 2);
    const uint16_t d3 = *((uint16_t*) v3);
    hash.num4[0] ^= d3;
    hash.num4[1] ^= d3;
    hash.num4[2] ^= d3;
    hash.num4[3] ^= d3;

    assert(hash_size == 8);
    memcpy(hash_return, &hash.data, 8);
}

int dht_random_bytes(void *buf, size_t size)
{
    return bytes_random(buf, size);
}

bool kad_setup(void)
{
    uint8_t node_id[SHA1_BIN_LENGTH];
    int af = gconf->af;

#ifdef DEBUG
    // Let the DHT output debug text
    dht_debug = stdout;
#endif

    bytes_random(node_id, SHA1_BIN_LENGTH);

    if (af == AF_INET || af == AF_UNSPEC) {
        g_dht_socket4 = net_bind("KAD", "0.0.0.0", gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP);
    }

    if (af == AF_INET6 || af == AF_UNSPEC) {
        g_dht_socket6 = net_bind("KAD", "::", gconf->dht_port, gconf->dht_ifname, IPPROTO_UDP);
    }

    if (g_dht_socket4 >= 0) {
        net_add_handler(g_dht_socket4, &dht_handler);
    }

    if (g_dht_socket6 >= 0) {
        net_add_handler(g_dht_socket6, &dht_handler);
    }

    if (g_dht_socket4 < 0 && g_dht_socket6 < 0) {
        return false;
    }

    // Init the DHT.  Also set the sockets into non-blocking mode.
    if (dht_init(g_dht_socket4, g_dht_socket6, node_id, (uint8_t*) "DD\0\0") < 0) {
        log_error("KAD: Failed to initialize the DHT.");
        return false;
    }

    return true;
}

void kad_free(void)
{
    dht_uninit();
}

static unsigned kad_count_bucket(const struct bucket *bucket, bool good)
{
    unsigned count = 0;

    while (bucket) {
        if (good) {
            struct node *node = bucket->nodes;
            while (node) {
                count += node_good(node) ? 1 : 0;
                node = node->next;
            }
        } else {
            count += bucket->count;
        }
        bucket = bucket->next;
    }

    return count;
}

int kad_count_nodes(bool good)
{
    // count nodes in IPv4 and IPv6 buckets
    return kad_count_bucket(buckets, good) + kad_count_bucket(buckets6, good);
}

void kad_status(FILE *fp)
{
    struct storage *strg = storage;
    struct search *srch = searches;
    struct announcement_t *announcement = announces_get();
    int numsearches4_active = 0;
    int numsearches4_done = 0;
    int numsearches6_active = 0;
    int numsearches6_done = 0;
    int numstorage = 0;
    int numstorage_peers = 0;
    int numannounces = 0;

    // Count searches
    while (srch) {
        if (srch->af == AF_INET6) {
            if (srch->done) {
                numsearches6_done += 1;
            } else {
                numsearches6_active += 1;
            }
        } else {
            if (srch->done) {
                numsearches4_done += 1;
            } else {
                numsearches4_active += 1;
            }
        }
        srch = srch->next;
    }

    // Count storage and peers
    while (strg) {
        numstorage_peers += strg->numpeers;
        numstorage += 1;
        strg = strg->next;
    }

    while (announcement) {
        numannounces += 1;
        announcement = announcement->next;
    }

    // Use dht data structure!
    int nodes4 = kad_count_bucket(buckets, false);
    int nodes6 = kad_count_bucket(buckets6, false);
    int nodes4_good = kad_count_bucket(buckets, true);
    int nodes6_good = kad_count_bucket(buckets6, true);

    clear_old_traffic_counters();
    uint32_t traffic_sum_in = 0;
    uint32_t traffic_sum_out = 0;
    for (size_t i = 0; i < TRAFFIC_DURATION_SECONDS; ++i) {
        traffic_sum_in += gconf->traffic_in[i];
        traffic_sum_out += gconf->traffic_out[i];
    }

    fprintf(
        fp,
        "%s\n"
        "DHT id: %s\n"
        "DHT uptime: %s\n"
        "DHT listen on: %s / device: %s / port: %d\n"
        "DHT nodes: %d IPv4 (%d good), %d IPv6 (%d good)\n"
        "DHT storage: %d entries with %d addresses\n"
        "DHT searches: %d IPv4 (%d done), %d IPv6 active (%d done)\n"
        "DHT announcements: %d\n"
        "DHT blocklist: %d\n"
        "DHT traffic: %s, %s/s (in) / %s, %s/s (out)\n",
        dhtd_version_str,
        str_id(myid),
        str_time(gconf->time_now - gconf->startup_time),
        str_af(gconf->af), gconf->dht_ifname ? gconf->dht_ifname : "<any>", gconf->dht_port,
        nodes4, nodes4_good, nodes6, nodes6_good,
        numstorage, numstorage_peers,
        numsearches4_active, numsearches4_done, numsearches6_active, numsearches6_done,
        numannounces,
        (next_blacklisted % DHT_MAX_BLACKLISTED),
        str_bytes(gconf->traffic_in_sum),
        str_bytes(traffic_sum_in / TRAFFIC_DURATION_SECONDS),
        str_bytes(gconf->traffic_out_sum),
        str_bytes(traffic_sum_out / TRAFFIC_DURATION_SECONDS)
    );
}

bool kad_ping(const IP* addr)
{
    return dht_ping_node((struct sockaddr *)addr, addr_len(addr)) >= 0;
}

bool kad_start_search(FILE *fp, const uint8_t id[], uint16_t port)
{
    int af = gconf->af;
    int rc4 = -1;
    int rc6 = -1;

    if (af == AF_UNSPEC || af == AF_INET) {
        rc4 = dht_search(id, port, AF_INET, dht_callback_func, NULL);
    }

    if (af == AF_UNSPEC || af == AF_INET6) {
        rc6 = dht_search(id, port, AF_INET6, dht_callback_func, NULL);
    }

    if (rc4 == 1 || rc6 == 1) {
        if (fp) fprintf(fp, "Search started.\n");
        return true;
    }

    if (rc4 == 0 || rc6 == 0) {
        if (fp) fprintf(fp, "Search in progress.\n");
        return true;
    }

    if (fp) fprintf(fp, "Failed to start search.\n");

    return false;
}

bool kad_block(const IP* addr)
{
    blacklist_node(NULL, (struct sockaddr *) addr, sizeof(IP));

    return true;
}

// Export known peers; the maximum is 400 nodes
int kad_export_peers(FILE *fp)
{
    // get number of good nodes
    int num4 = kad_count_bucket(buckets, true);
    int num6 = kad_count_bucket(buckets6, true);

    IP4 *addr4 = (IP4*) malloc(num4 * sizeof(IP4));
    IP6 *addr6 = (IP6*) malloc(num6 * sizeof(IP6));

    if (addr4 == NULL) {
        num4 = 0;
    }

    if (addr6 == NULL) {
        num6 = 0;
    }

    dht_get_nodes(addr4, &num4, addr6, &num6);

    for (size_t i = 0; i < num4; ++i) {
#ifdef __CYGWIN__
        fprintf(fp, "%s\r\n", str_addr((IP*) &addr4[i]));
#else
        fprintf(fp, "%s\n", str_addr((IP*) &addr4[i]));
#endif
    }

    for (size_t i = 0; i < num6; ++i) {
#ifdef __CYGWIN__
        fprintf(fp, "%s\r\n", str_addr((IP*) &addr6[i]));
#else
        fprintf(fp, "%s\n", str_addr((IP*) &addr6[i]));
#endif
    }

    if (addr4) {
        free(addr4);
    }

    if (addr6) {
        free(addr6);
    }

    return num4 + num6;
}

static void kad_print_buckets_interal(FILE* fp, int af, const struct bucket *b)
{
    unsigned bucket_i, node_i, all_nodes = 0;

    for (bucket_i = 0; b; ++bucket_i) {
        fprintf(fp, " bucket: %s\n", str_id(b->first));

        struct node *n = b->nodes;
        for (node_i = 0; n; ++node_i) {
            fprintf(fp, "   id: %s\n", str_id(n->id));
            fprintf(fp, "	 address: %s\n", str_addr(&n->ss));
            fprintf(fp, "	 pinged: %d\n", n->pinged);
            n = n->next;
        }
        fprintf(fp, "  %u nodes.\n", node_i);
        all_nodes += node_i;
        b = b->next;
    }

    fprintf(fp, "Found %u %s buckets with %u nodes.\n", bucket_i, (af == AF_INET) ? "IPv4" : "IPv6", all_nodes);
}

// Print buckets (leaf/finger table)
void kad_print_buckets(FILE* fp)
{
    int af = gconf->af;

    if (af == AF_UNSPEC || af == AF_INET) {
        kad_print_buckets_interal(fp, AF_INET, buckets);
    }

    if (af == AF_UNSPEC || af == AF_INET6) {
        kad_print_buckets_interal(fp, AF_INET6, buckets6);
    }
}

// Print searches
void kad_print_searches(FILE *fp)
{
    size_t i;

    struct search *s = searches;
    for (i = 0; s; ++i) {
        fprintf(fp, " id: %s\n", str_id(s->id));
        fprintf(fp, "  net: %s, port: %u, done: %s\n",
            (s->af == AF_INET) ? "IPv4" : "IPv6",
            (unsigned) s->port,
            s->done ? "true" : "false"
        );
        fprintf(fp, "  results: %u\n", (unsigned) results_count(s->id, s->af));
        /*
        if (do_print_nodes) {
            for (j = 0; j < s->numnodes; ++j) {
                struct search_node *sn = &s->nodes[j];
                fprintf(fp, "   node: %s\n", str_id(sn->id));
                fprintf(fp, "	 address: %s\n", str_addr(&sn->ss));
                fprintf(fp, "	 pinged: %d, pinged: %d, acked: %d\n",
                    sn->pinged, sn->replied, sn->acked);
            }
            fprintf(fp, "  Found %u nodes.\n", (unsigned) j);
        } else {
            fprintf(fp, "  nodes: %u\n", (unsigned) s->numnodes);
        }*/
        s = s->next;
    }

    fprintf(fp, " Found %u searches\n", (unsigned) i);
}

// Print announced ids we have received
void kad_print_storage(FILE *fp)
{
    size_t i, j;

    struct storage *s = storage;
    for (i = 0; s; ++i) {
        fprintf(fp, " id: %s\n", str_id(s->id));
        for (j = 0; j < s->numpeers; ++j) {
            struct peer *p = &s->peers[j];
            fprintf(fp, "   address: %s\n", str_addr2(&p->ip[0], p->len, p->port));
        }
        fprintf(fp, "  Found %u addresses.\n", (unsigned) j);
        s = s->next;
    }
    fprintf(fp, " Found %u stored hashes from received announcements.\n", (unsigned) i);
}

void kad_print_blocklist(FILE *fp)
{
    size_t i;

    for (i = 0; i < (next_blacklisted % DHT_MAX_BLACKLISTED); i++) {
        fprintf(fp, " %s\n", str_addr(&blacklist[i]));
    }

    fprintf(fp, " Found %u blocked addresses.\n", (unsigned) i);
}

void kad_print_constants(FILE *fp)
{
    fprintf(fp, "DHT_SEARCH_EXPIRE_TIME: %d\n", DHT_SEARCH_EXPIRE_TIME);
    fprintf(fp, "DHT_MAX_SEARCHES: %d\n", DHT_MAX_SEARCHES);

    // Maximum number of announced hashes we track
    fprintf(fp, "DHT_MAX_HASHES: %d\n", DHT_MAX_HASHES);

    // Maximum number of peers for each announced hash we track
    fprintf(fp, "DHT_MAX_PEERS: %d\n", DHT_MAX_PEERS);

    // Maximum number of blocked nodes
    fprintf(fp, "DHT_MAX_BLACKLISTED: %d\n", DHT_MAX_BLACKLISTED);

    fprintf(fp, "MAX_RESULTS_PER_SEARCH: %d\n", MAX_RESULTS_PER_SEARCH);
}
