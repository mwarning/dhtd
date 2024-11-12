#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "results.h"


/*
* The DHT implementation in DHTd does not store
* results (IP addresses) from hash id searches.
* Therefore, results are collected and stored here.
*/

#ifndef AF_INET6_CONST
    #define AF_INET6_CONST 10  // Standard value for IPv6 (adjust if needed)
#else
    #define AF_INET6_CONST AF_INET6  // Use the system's AF_INET6 directly
#endif

struct result_t {
    uint8_t ip[16];
    uint8_t length;
    uint16_t port;
    struct result_t *next;
};

struct search_t {
    uint8_t id[SHA1_BIN_LENGTH];
    uint16_t numresults4;
    uint16_t numresults6;
    uint16_t maxresults; // IPv4 + IPv6
    struct result_t *results;
    struct search_t *next;
};

// A ring buffer for all searches
static struct search_t *g_searches = NULL;


static struct search_t *find_search(const uint8_t id[])
{
    struct search_t *search = g_searches;
    while (search) {
        if (memcmp(&search->id, id, SHA1_BIN_LENGTH) == 0) {
            return search;
        }
        search = search->next;
    }

    return NULL;
}

static struct result_t *find_result(const struct search_t *search, const uint8_t ip[16], uint16_t length, uint16_t port)
{
    struct result_t *result = search->results;
    while (result) {
        if (length == result->length && 0 == memcmp(ip, &result->ip, length) && port == result->port) {
            return result;
        }
        result = result->next;
    }

    return NULL;
}

static void on_new_search_result(const char *path, const uint8_t id[], const uint8_t *ip, uint8_t length, uint16_t port)
{
    char command[1024];

    // call script if configured
    int n = snprintf(command, sizeof(command), "%s %s %s &",
        path, str_id(id), str_addr2(ip, length, port)
    );

    if (n > 0 && n < sizeof(command)) {
        system(command);
    } else {
        log_error("system() command too long");
    }
}

struct dht_addr4_t {
    uint8_t addr[4];
    uint16_t port;
};

struct dht_addr6_t {
    uint8_t addr[16];
    uint16_t port;
};

static void result_add(struct search_t *search, const uint8_t id[], const uint8_t *ip, uint8_t length, uint16_t port)
{
    struct result_t *result = find_result(search, ip, length, port);
    if (!result) {
        // add new result
        result = calloc(1, sizeof(struct result_t));
        memcpy(&result->ip, ip, length);
        result->length = length;
        result->port = port;

        result->next = search->results;
        search->results = result;

        if (length == 4) {
            search->numresults4 += 1;
        } else {
            search->numresults6 += 1;
        }

        if (gconf->execute_path) {
            on_new_search_result(gconf->execute_path, id, ip, length, port);
        }
    }
}

void results_add(const uint8_t id[], int af, const void *data, size_t data_len)
{
    struct search_t *search = find_search(id);
    if (!search) {
        // add new search
        search = calloc(1, sizeof(struct search_t));
        memcpy(&search->id, id, SHA1_BIN_LENGTH);
        search->maxresults = MAX_RESULTS_PER_SEARCH;

        search->next = g_searches;
        g_searches = search;
    }

    // current results
    int numresults = search->numresults4 + search->numresults6;

    switch (af) {
        case AF_INET: {
            size_t got = (data_len / sizeof(struct dht_addr4_t));
            size_t add = MIN(got, search->maxresults - numresults);
            struct dht_addr4_t *data4 = (struct dht_addr4_t *) data;
            for (size_t i = 0; i < add; ++i) {
                result_add(search, id, &data4[i].addr[0], 4, (uint16_t) data4[i].port);
            }
            break;
        }
        case AF_INET6_CONST: {
            size_t got = (data_len / sizeof(struct dht_addr6_t));
            size_t add = MIN(got, search->maxresults - numresults);
            struct dht_addr6_t *data6 = (struct dht_addr6_t *) data;
            for (size_t i = 0; i < add; ++i) {
                result_add(search, id, &data6[i].addr[0], 16, (uint16_t) data6[i].port);
            }
        }
    }
}

unsigned results_count(const uint8_t id[], int af)
{
    struct search_t *search = find_search(id);
    if (search) switch (af) {
        case AF_INET: return search->numresults4;
        case AF_INET6_CONST: return search->numresults6;
        default: return search->numresults4 + search->numresults6;
    }
    return 0;
}

bool results_print(FILE *fp, const uint8_t id[])
{
    struct search_t *search = find_search(id);

    if (search) {
        struct result_t *result = search->results;
        while (result) {
            fprintf(fp, "%s\n", str_addr2(&result->ip[0], result->length, result->port));
            result = result->next;
        }
        return true;
    }

    return false;
}

// Free a search_t struct
static void search_free(struct search_t *search)
{
    struct result_t *cur;
    struct result_t *next;

    cur = search->results;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    free(search);
}

void results_clear(const uint8_t id[])
{
    struct search_t* prev = NULL;
    struct search_t* search = g_searches;

    while (search) {
        if (memcmp(search->id, id, SHA1_BIN_LENGTH) == 0) {
            // remove search from list and free
            if (prev) {
                prev->next = search->next;
            } else {
                g_searches = search->next;
            }
            search_free(search);
            break;
        }
        prev = search;
        search = search->next;
    }
}
