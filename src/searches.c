
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "log.h"
#include "main.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "searches.h"


/*
* The DHT implementation in DHTd does not store
* results (IP addresses) from hash id searches.
* Therefore, results are collected and stored here.
*/

// Expected lifetime of announcements
#define MAX_SEARCH_LIFETIME (20*60)
#define MAX_RESULTS_PER_SEARCH 16

// A ring buffer for all searches
static struct search_t *g_searches = NULL;


struct search_t *searches_find(const uint8_t id[])
{
	struct search_t *search;

	search = g_searches;
	while (search) {
		if (memcmp(search->id, id, SHA1_BIN_LENGTH) == 0) {
			return search;
		}
		search = search->next;
	}

	return NULL;
}

// Free a search_t struct
void search_free(struct search_t *search)
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

int searches_count()
{
	struct search_t *search;
	int count = 0;

	search = g_searches;
	while (search) {
		count += 1;
		search = search->next;
	}

	return count;
}

void searches_debug(FILE *fp)
{
	struct search_t *search;
	struct result_t *result;
	int result_counter;
	int search_counter;

	fprintf(fp, "Searches:\n");

	search_counter = 0;
	search = g_searches;
	while (search) {
		fprintf(fp, " id: %s\n", str_id(search->id));
		fprintf(fp, "  done: %s\n", search->done ? "true" : "false");
		fprintf(fp, "  started: %ldm ago\n", (time_now_sec() - search->start_time) / 60);
		result_counter = 0;
		result = search->results;
		while (result) {
			fprintf(fp, "   addr: %s\n", str_addr(&result->addr));
			result_counter += 1;
			result = result->next;
		}
		fprintf(fp, "  Found %d results\n", result_counter);
		result_counter += 1;
		search_counter += 1;
		search = search->next;
	}

	fprintf(fp, " Found %d searches\n", search_counter);
}

// Start a new search for a sanitized query
struct search_t* searches_start(const uint8_t id[])
{
	struct search_t* search;

	// Find existing search
	if ((search = searches_find(id)) != NULL) {
		// Restart search after half of search lifetime
		if ((time_now_sec() - search->start_time) > (MAX_SEARCH_LIFETIME / 2)) {
			search->start_time = time_now_sec();
			search->done = 0;
		}

		return search;
	}


	search = calloc(1, sizeof(struct search_t));
	memcpy(search->id, id, SHA1_BIN_LENGTH);
	search->start_time = time_now_sec();

	log_debug("Searches: Create new search for id: %s", str_id(id));

	// prepend search
	search->next = g_searches;
	g_searches = search;

	return search;
}

bool searches_stop(const uint8_t id[])
{
	struct search_t* search;
	struct search_t* prev;

	prev = NULL;
	search = g_searches;
	while (search) {
		if (memcmp(search->id, id, SHA1_BIN_LENGTH) == 0) {
			if (prev) {
				prev->next = search->next;
			} else {
				g_searches = search->next;
			}
			search_free(search);
			return true;
		}
		prev = search;
		search = search->next;
	}

	return false;
}

// Add a resolved address to the search
void searches_add_addr(struct search_t *search, const IP *addr)
{
	struct result_t *cur;
	struct result_t *new;
	struct result_t *last;
	int count;

	if (search->done) {
		// No need to add more addresses
		return;
	}

	// Check if result already exists
	// or maximum result count is reached
	count = 0;
	last = NULL;
	cur = search->results;
	while (cur) {
		last = cur;

		if (addr_equal(&cur->addr, addr)) {
			// Address already listed
			return;
		}

		if (count > MAX_RESULTS_PER_SEARCH) {
			return;
		}

		count += 1;
		cur = cur->next;
	}

	new = calloc(1, sizeof(struct result_t));
	memcpy(&new->addr, addr, sizeof(IP));

	// Append new entry to list
	if (last) {
		last->next = new;
	} else {
		search->results = new;
	}

	// call script if configured
	if (gconf->execute_path) {
		char command[1024];
		int n = snprintf(command, sizeof(command), "%s %s %s &", gconf->execute_path, str_id(search->id), str_addr(&new->addr));
		if (n > 0 && n < sizeof(command)) {
			system(command);
		} else {
			log_error("Searches: command too long");
		}
	}
}

void searches_setup(void)
{
	// Nothing to do
}

void searches_free(void)
{
	struct search_t *search;
	struct search_t *prev;

	prev = NULL;
	search = g_searches;
	while (search) {
		prev = search;
		search = search->next;
		search_free(prev);
	}

	g_searches = NULL;
}
