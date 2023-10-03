
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "log.h"
#include "conf.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "announces.h"


// Announce values every 20 minutes
#define ANNOUNCES_INTERVAL (20*60)


static time_t g_announces_expire = 0;
static time_t g_announces_announce = 0;
static struct announcement_t *g_values = NULL;


struct announcement_t* announces_get(void)
{
	return g_values;
}

struct announcement_t* announces_find(const uint8_t id[])
{
	struct announcement_t *value;

	value = g_values;
	while (value) {
		if (id_equal(id, value->id)) {
			return value;
		}
		value = value->next;
	}
	return NULL;
}

int announces_count()
{
	struct announcement_t *value;
	int count = 0;

	value = g_values;
	while (value) {
		count += 1;
		value = value->next;
	}

	return count;
}

void announces_debug(FILE *fp)
{
	struct announcement_t *value;
	time_t now;
	int nodes_counter;
	int value_counter;

	now = time_now_sec();
	value_counter = 0;
	nodes_counter = kad_count_nodes(0);
	value = g_values;

	fprintf(fp, "Announcements:\n");
	fprintf(fp, "interval: %dm\n", ANNOUNCES_INTERVAL / 60);
	while (value) {
		fprintf(fp, " id: %s\n", str_id(value->id));
		fprintf(fp, "  port: %d\n", value->port);
		if (value->refresh < now) {
			if (nodes_counter > 0) {
				fprintf(fp, "  refresh: now\n");
			} else {
				// no nodes we can announce to
				fprintf(fp, "  refresh: wait\n");
			}
		} else {
			fprintf(fp, "  refresh: in %ld min\n", (value->refresh - now) / 60);
		}

		if (value->lifetime == LONG_MAX) {
			fprintf(fp, "  lifetime: entire runtime\n");
		} else {
			fprintf(fp, "  lifetime: %ld min left\n", (value->lifetime -  now) / 60);
		}

		value_counter++;
		value = value->next;
	}

	fprintf(fp, " Found %d entries.\n", value_counter);
}

// Announce a sanitized query
struct announcement_t *announces_add(uint8_t id[], int port, time_t lifetime)
{
	struct announcement_t *cur;
	struct announcement_t *new;
	time_t now = time_now_sec();

	// Value already exists - refresh
	if ((cur = announces_find(id)) != NULL) {
		cur->refresh = now - 1;

		if (lifetime > now) {
			cur->lifetime = lifetime;
		}

		// Trigger immediate handling
		g_announces_announce = 0;

		return cur;
	}

	// Prepend new entry
	new = (struct announcement_t*) calloc(1, sizeof(struct announcement_t));
	memcpy(new->id, id, SHA1_BIN_LENGTH);
	new->port = port;
	new->refresh = now - 1; // Send first announcement as soon as possible
	new->lifetime = lifetime;

	if (lifetime == LONG_MAX) {
		log_debug("Add announcement for %s:%hu. Keep alive for entire runtime.", str_id(id), port);
	} else {
		log_debug("Add announcement for %s:%hu. Keep alive for %lu minutes.", str_id(id), port, (lifetime - now) / 60);
	}

	// Prepend to list
	new->next = g_values;
	g_values = new;

	// Trigger immediate handling
	g_announces_announce = 0;

	return new;
}

void value_free(struct announcement_t *value)
{
	free(value);
}

static void announces_expire(void)
{
	struct announcement_t *pre;
	struct announcement_t *cur;
	time_t now;

	now = time_now_sec();
	pre = NULL;
	cur = g_values;
	while (cur) {
		if (cur->lifetime < now) {
			if (pre) {
				pre->next = cur->next;
			} else {
				g_values = cur->next;
			}
			value_free(cur);
			return;
		}
		pre = cur;
		cur = cur->next;
	}
}

static void announces_announce(void)
{
	struct announcement_t *value;
	time_t now;

	now = time_now_sec();
	value = g_values;
	while (value) {
		if (value->refresh < now) {
			log_debug("Announce %s:%hu", str_id(value->id), value->port);
			kad_announce_once(value->id, value->port);
			value->refresh = now + ANNOUNCES_INTERVAL;
		}
		value = value->next;
	}
}

static void announces_handle(int _rc, int _sock)
{
	// Expire search results
	if (g_announces_expire <= time_now_sec()) {
		announces_expire();

		// Try again in ~1 minute
		g_announces_expire = time_add_mins(1);
	}

	if (g_announces_announce <= time_now_sec() && kad_count_nodes(0) != 0) {
		announces_announce();

		// Try again in ~1 minute
		g_announces_announce = time_add_mins(1);
	}
}

void announces_setup(void)
{
	// Cause the callback to be called in intervals
	net_add_handler(-1, &announces_handle);
}

void announces_free(void)
{
	struct announcement_t *cur;
	struct announcement_t *next;

	cur = g_values;
	while (cur) {
		next = cur->next;
		value_free(cur);
		cur = next;
	}
	g_values = NULL;
}
