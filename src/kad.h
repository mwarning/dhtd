
#ifndef _KAD_H_
#define _KAD_H_

/*
* Interface to interact with the DHT implementation.
*/

bool kad_setup(void);
void kad_free(void);

// Ping this node to add it to the node table
bool kad_ping(const IP *addr);

// Block a specific address
bool kad_block(const IP* addr);

bool kad_start_search(FILE *fp, const uint8_t id[], uint16_t port);

// Export good peers
int kad_export_peers(FILE *fp);

// Print status information
void kad_status(FILE *fp);

// Count good or all known peers
int kad_count_nodes(bool good);

// Announce query until lifetime expires.
bool kad_announce(const uint8_t id[], int port, time_t lifetime);

void kad_print_buckets(FILE *fp);
void kad_print_searches(FILE *fp);
void kad_print_storage(FILE *fp);
void kad_print_blocklist(FILE *fp);
void kad_print_constants(FILE *fp);

#endif // _KAD_H_
