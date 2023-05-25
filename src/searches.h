
#ifndef _EXT_SEARCHES_H_
#define _EXT_SEARCHES_H_

#include <stdio.h>

// An address that was received as a result of an id search
struct result_t {
	struct result_t *next;
	IP addr;
};

// A bucket of results received when in search of an id
struct search_t {
	struct search_t *next;
	uint8_t id[SHA1_BIN_LENGTH];
	uint16_t done;
	char query[QUERY_MAX_SIZE];
	time_t start_time;
	struct result_t *results;
};

void searches_setup(void);
void searches_free(void);

// Start a search
struct search_t *searches_start(const char query[]);

// Find a search by infohash, so we can add results
struct search_t *searches_find_by_id(const uint8_t id[]);

// Add an address to a result bucket
void searches_add_addr(struct search_t *search, const IP *addr);

void searches_debug(FILE *fp);


#endif // _EXT_SEARCHES_H_
