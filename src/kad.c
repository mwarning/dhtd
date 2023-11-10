
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

// include dht.c instead of dht.h to access private vars
#include "dht.c"


/*
* The interface that is used to interact with the DHT.
*/

// Next time to do DHT maintenance
static time_t g_dht_maintenance = 0;
static int g_dht_socket4 = -1;
static int g_dht_socket6 = -1;


/*
* Put an address and port into a sockaddr_storages struct.
* Both addr and port are in network byte order.
*/
void to_addr(IP *out_addr, const void *in_addr, size_t len, uint16_t port)
{
	memset(out_addr, '\0', sizeof(IP));

	if (len == 4) {
		IP4 *a = (IP4 *) out_addr;
		a->sin_family = AF_INET;
		a->sin_port = port;
		memcpy(&a->sin_addr.s_addr, in_addr, 4);
	}

	if (len == 16) {
		IP6 *a = (IP6 *) out_addr;
		a->sin6_family = AF_INET6;
		a->sin6_port = port;
		memcpy(&a->sin6_addr.s6_addr, in_addr, 16);
	}
}

static void on_new_search_result(const uint8_t id[], const IP *address)
{
	char command[1024];

	log_debug("on_new_search_result: %s %s", str_id(id), str_addr(address));

	// call script if configured
	if (gconf->execute_path) {
		int n = snprintf(command, sizeof(command), "%s %s %s &", gconf->execute_path, str_id(id), str_addr(address));
		if (n > 0 && n < sizeof(command)) {
			system(command);
		} else {
			log_error("kad: command too long");
		}
	}
}

typedef struct {
	uint8_t addr[16];
	uint16_t port;
} dht_addr6_t;

typedef struct {
	uint8_t addr[4];
	uint16_t port;
} dht_addr4_t;


// This callback is called when a search result arrives or a search completes
void dht_callback_func(void *closure, int event, const uint8_t *info_hash, const void *data, size_t data_len)
{
	dht_addr4_t *data4;
	dht_addr6_t *data6;
	IP address;

	switch (event) {
		case DHT_EVENT_VALUES:
			data4 = (dht_addr4_t *) data;
			for (int i = 0; i < (data_len / sizeof(dht_addr4_t)); ++i) {
				to_addr(&address, &data4[i].addr, 4, data4[i].port);
				on_new_search_result(info_hash, &address);
			}
			break;
		case DHT_EVENT_VALUES6:
			data6 = (dht_addr6_t *) data;
			for (int i = 0; i < (data_len / sizeof(dht_addr6_t)); ++i) {
				to_addr(&address, &data6[i].addr, 16, data6[i].port);
				on_new_search_result(info_hash, &address);
			}
			break;
		case DHT_EVENT_SEARCH_DONE:
		case DHT_EVENT_SEARCH_DONE6:
			break;
	}
}

// Handle incoming packets and pass them to the DHT code
void dht_handler(int rc, int sock)
{
	uint8_t buf[1500];
	uint32_t buflen;
	IP from;
	socklen_t fromlen;
	time_t time_wait = 0;

	if (rc > 0) {
		// Check which socket received the data
		fromlen = sizeof(from);
		buflen = recvfrom(sock, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &from, &fromlen);

		if (buflen <= 0 || buflen >= sizeof(buf)) {
			return;
		}

		// The DHT code expects the message to be null-terminated.
		buf[buflen] = '\0';
	} else {
		buflen = 0;
	}

	if (buflen > 0) {
		// Handle incoming data
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

int dht_sendto(int sockfd, const void *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
	return sendto(sockfd, buf, len, flags, to, tolen);
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
	//dht_debug = stdout;
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

	fprintf(
		fp,
		"%s\n"
		"DHT id: %s\n"
		"DHT listen on: %s / %s\n"
		"DHT nodes: %d IPv4 (%d good), %d IPv6 (%d good)\n"
		"DHT storage: %d entries with %d addresses\n"
		"DHT searches: %d IPv4 (%d done), %d IPv6 active (%d done)\n"
		"DHT announcements: %d\n"
		"DHT blacklist: %d\n",
		dhtd_version_str,
		str_id(myid),
		str_af(gconf->af), gconf->dht_ifname ? gconf->dht_ifname : "<any>",
		nodes4, nodes4_good, nodes6, nodes6_good,
		numstorage, numstorage_peers,
		numsearches4_active, numsearches4_done, numsearches6_active, numsearches6_done,
		numannounces,
		(next_blacklisted % DHT_MAX_BLACKLISTED)
	);
}

bool kad_ping(const IP* addr)
{
	return dht_ping_node((struct sockaddr *)addr, addr_len(addr)) >= 0;
}

void kad_print_results(FILE *fp, const uint8_t id[])
{
	IP address;
	unsigned count = 0;

	struct storage *st = find_storage(id);
	if (st) {
		for (size_t i = 0; i < st->numpeers; i++) {
			uint16_t port = htons(st->peers[i].port);
			switch (st->peers[i].len) {
			case 4:
				to_addr(&address, st->peers[i].ip, 4, port);
				count++;
				break;
			case 16:
				to_addr(&address, st->peers[i].ip, 16, port);
				count++;
				break;
			default:
				continue;
			}
			fprintf(fp, "%s\n", str_addr(&address));
		}
	}
	fprintf(fp, "Found %u results.\n", (unsigned) count);
}

bool kad_start_search(FILE *fp, const uint8_t id[], uint16_t port)
{
	int af = gconf->af;
	int rc4 = -1;
	int rc6 = -1;

	//log_debug("KAD: Start DHT search %s:%hu", str_id(id), port);

	if (af == AF_UNSPEC || af == AF_INET) {
		rc4 = dht_search(id, port, AF_INET, NULL /*dht_callback_func*/, NULL);
	}

	if (af == AF_UNSPEC || af == AF_INET6) {
		rc6 = dht_search(id, port, AF_INET6, NULL /*dht_callback_func*/, NULL);
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

bool kad_stop_search(FILE *fp, const uint8_t id[])
{
	struct search *search = searches;

	while (search) {
		if (memcmp(search->id, id, SHA1_BIN_LENGTH) == 0) {
			break;
		}
		search = search->next;
	}

	if (search) {
		if (search->done) {
			if (fp) fprintf(fp, "Search already done.\n");
		} else {
			search->done = 1;
			if (fp) fprintf(fp, "Search stopped.\n");
		}
		return true;
	} else {
		if (fp) fprintf(fp, "Search not found.\n");
		return false;
	}
}

/*
* Search the address of the node whose node id matches id.
* The search will be performed on the results of kad_search().
* The port in the returned address refers to the kad instance.
*/
void kad_print_node_addresses(FILE *fp, const uint8_t id[])
{
	struct search *sr = searches;
	while (sr) {
		if (sr->af == gconf->af && id_equal(sr->id, id)) {
			for (size_t i = 0; i < sr->numnodes; ++i) {
				if (id_equal(sr->nodes[i].id, id)) {
					fprintf(fp, "%s", str_addr(&sr->nodes[i].ss));
				}
			}
		}
		sr = sr->next;
	}
}

bool kad_blacklist(const IP* addr)
{
	blacklist_node(NULL, (struct sockaddr *) addr, sizeof(IP));

	return true;
}

// Export known peers; the maximum is 300 nodes
int kad_export_peers(FILE *fp)
{
	IP4 addr4[150];
	IP6 addr6[150];
	int num4;
	int num6;
	int i;

	num6 = ARRAY_SIZE(addr4);
	num4 = ARRAY_SIZE(addr6);

	dht_get_nodes(addr4, &num4, addr6, &num6);

	for (i = 0; i < num4; i++) {
#ifdef __CYGWIN__
		fprintf(fp, "%s\r\n", str_addr((IP*) &addr4[i]));
#else
		fprintf(fp, "%s\n", str_addr((IP*) &addr4[i]));
#endif
	}

	for (i = 0; i < num6; i++) {
#ifdef __CYGWIN__
		fprintf(fp, "%s\r\n", str_addr((IP*) &addr6[i]));
#else
		fprintf(fp, "%s\n", str_addr((IP*) &addr6[i]));
#endif
	}

	return num4 + num6;
}

// Print buckets (leaf/finger table)
void kad_print_buckets(FILE* fp)
{
	size_t i, j;

	struct bucket *b = (gconf->af == AF_INET) ? buckets : buckets6;
	for (j = 0; b; ++j) {
		fprintf(fp, " bucket: %s\n", str_id(b->first));

		struct node * n = b->nodes;
		for (i = 0; n; ++i) {
			fprintf(fp, "   id: %s\n", str_id(n->id));
			fprintf(fp, "     address: %s\n", str_addr(&n->ss));
			fprintf(fp, "     pinged: %d\n", n->pinged);
			n = n->next;
		}
		fprintf(fp, "  Found %u nodes.\n", (unsigned) i);
		b = b->next;
	}
	fprintf(fp, "Found %u buckets.\n", (unsigned) j);
}

// Print searches
void kad_print_searches(FILE *fp, bool do_print_nodes)
{
	size_t i, j;

	struct search *s = searches;
	for (i = 0; s; ++i) {
		fprintf(fp, " id: %s\n", str_id(s->id));
		fprintf(fp, "  net: %s, port: %u, done: %s\n",
			(s->af == AF_INET) ? "IPv4" : "IPv6",
			(unsigned) s->port,
			s->done ? "true" : "false"
		);
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
		}
		s = s->next;
	}

	fprintf(fp, " Found %u searches\n", (unsigned) i);
}

// Print announced ids we have received
void kad_print_storage(FILE *fp)
{
	IP addr;
	size_t i, j;

	struct storage *s = storage;
	for (i = 0; s; ++i) {
		fprintf(fp, " id: %s\n", str_id(s->id));
		for (j = 0; j < s->numpeers; ++j) {
			struct peer *p = &s->peers[j];
			to_addr(&addr, &p->ip, p->len, htons(p->port));
			fprintf(fp, "   peer: %s\n", str_addr(&addr));
		}
		fprintf(fp, "  Found %u peers.\n", (unsigned) j);
		s = s->next;
	}
	fprintf(fp, " Found %u stored hashes from received announcements.\n", (unsigned) i);
}

void kad_print_blacklist(FILE *fp)
{
	size_t i;

	for (i = 0; i < (next_blacklisted % DHT_MAX_BLACKLISTED); i++) {
		fprintf(fp, " %s\n", str_addr(&blacklist[i]));
	}

	fprintf(fp, " Found %u blacklisted addresses.\n", (unsigned) i);
}

void kad_print_constants(FILE *fp)
{
	fprintf(fp, "DHT_SEARCH_EXPIRE_TIME: %d\n", DHT_SEARCH_EXPIRE_TIME);
	fprintf(fp, "DHT_MAX_SEARCHES: %d\n", DHT_MAX_SEARCHES);

	// Maximum number of announced hashes we track
	fprintf(fp, "DHT_MAX_HASHES: %d\n", DHT_MAX_HASHES);

	// Maximum number of peers for each announced hash we track
	fprintf(fp, "DHT_MAX_PEERS: %d\n", DHT_MAX_PEERS);

	// Maximum number of blacklisted nodes
	fprintf(fp, "DHT_MAX_BLACKLISTED: %d\n", DHT_MAX_BLACKLISTED);
}
