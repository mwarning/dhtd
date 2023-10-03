
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "kad.h"
#include "net.h"
#include "unix.h"
#include "announces.h"
#include "searches.h"
#include "ext-cmd.h"


static const char *g_client_usage =
PROGRAM_NAME" Control Program - Send commands to a DHTd instance.\n\n"
"Usage: dhtd-ctl [OPTIONS] [COMMANDS]\n"
"\n"
" -p <file>	Connect to this unix socket (Default: "CMD_PATH")\n"
" -h		Print this help.\n"
"\n";

static const char* g_server_usage =
	"Usage:\n"
	"	status\n"
	"	search [start|stop] <query>\n"
	"	announce [<query>[:<port>] [<minutes>]]\n"
	"	ping <addr>\n";

const char* g_server_usage_debug =
	"	blacklist <addr>\n"
	"	list blacklist|searches|announcements|peers"
	"|constants\n"
	"	list dht_buckets|dht_searches|dht_storage\n";

static int g_cmd_sock = -1;


static int cmd_ping(FILE *fp, const char addr_str[], int af)
{
	IP addr;

	if (addr_parse(&addr, addr_str, STR(DHT_PORT), af)) {
		if (kad_ping(&addr)) {
			fprintf(fp, "Send ping to: %s\n", str_addr(&addr));
			return 1;
		} else {
			fprintf(fp, "Failed to send ping.\n");
		}
	}

	return 0;
}

static void cmd_blacklist(FILE *fp, const char *addr_str)
{
	IP addr;

	if (addr_parse(&addr, addr_str, NULL, gconf->af)) {
		kad_blacklist(&addr);
		fprintf(fp, "Added to blacklist: %s\n", str_addr(&addr));
	} else {
		fprintf(fp, "Invalid address.\n");
	}
}

static void cmd_announce(FILE *fp, const char query[], int port, int minutes)
{
	time_t lifetime;
	uint8_t id[SHA1_BIN_LENGTH];

	if (minutes < 0) {
		lifetime = LONG_MAX;
	} else {
		// Round up to multiple of 30 minutes
		minutes = (30 * (minutes / 30 + 1));
		lifetime = (time_now_sec() + (minutes * 60));
	}

	if (port < 1 || port > 65535) {
		port = gconf->dht_port;
	}

	if (!parse_hex_id(id, sizeof(id), query, strlen(query))) {
		fprintf(fp, "Invalid query: %s (no 20 byte hex string)\n", query);
	} else if(announces_add(id, port, lifetime)) {
		if (minutes < 0) {
			fprintf(fp, "Start regular announcements for the entire run time (port %d).\n", port);
		} else {
			fprintf(fp, "Start regular announcements for %d minutes (port %d).\n", minutes, port);
		}
	} else {
		fprintf(fp, "Failed to add announcement.\n");
	}
}

// Match a format string with only %n at the end
static int match(const char request[], const char fmt[])
{
	int n = -1;
	sscanf(request, fmt, &n);
	return (n > 0 && request[n] == '\0');
}

static void cmd_exec(FILE *fp, const char request[], int allow_debug)
{
	const struct search_t *search;
	const struct result_t *result;
	const struct announcement_t *value;
	int minutes;
	int found;
	char query[256];
	char address[256];
	uint8_t id[SHA1_BIN_LENGTH];
	int count;
	int port;
	char d; // dummy marker

	if (sscanf(request, " ping%*[ ]%255[^ \n\t] %c", address, &d) == 1) {
		if (gconf->af == AF_UNSPEC) {
			count = cmd_ping(fp, address, AF_INET);
			count += cmd_ping(fp, address, AF_INET6);
		} else {
			count = cmd_ping(fp, address, gconf->af);
		}

		if (count == 0) {
			fprintf(fp, "Failed to parse/resolve address.\n");
		}
	} else if (sscanf(request, " search stop%*[ ]%255[^: \n\t] %c", query, &d) == 1) {
		if (parse_hex_id(id, sizeof(id), query, strlen(query))) {
			if (kad_search_stop(id)) {
				fprintf(fp, "Done.\n");
			} else {
				fprintf(fp, "Search does not exist.\n");
			}
		} else {
			fprintf(fp, "Failed to parse hex id: %s\n", query);
		}
	} else if (sscanf(request, " search start%*[ ]%255[^: \n\t] %c", query, &d) == 1) {
		if (parse_hex_id(id, sizeof(id), query, strlen(query))) {
			// search hex query
			search = kad_search_start(id);

			if (search) {
				found = 0;
				for (result = search->results; result; result = result->next) {
					fprintf(fp, "%s\n", str_addr(&result->addr));
					found = 1;
				}

				if (!found) {
					if (search->start_time == time_now_sec()) {
						fprintf(fp, "Search started.\n");
					} else {
						fprintf(fp, "Search in progress.\n");
					}
				}
			} else {
				fprintf(fp, "Some error occurred.\n");
			}
		} else {
			fprintf(fp, "Failed to parse hex id: %s\n", query);
		}
	} else if (match(request, " status %n")) {
		// Print node id and statistics
		kad_status(fp);
	} else if (match(request, " announce %n")) {
		// Announce all values
		count = 0;
		value = announces_get();
		while (value) {
			kad_announce_once(value->id, value->port);
			fprintf(fp, " announce %s:%d\n", str_id(&value->id[0]), value->port);
			count += 1;
			value = value->next;
		}
		fprintf(fp, "Started %d announcements.\n", count);
	} else if (sscanf(request, " announce%*[ ]%255[^: \n\t] %c", query, &d) == 1) {
		cmd_announce(fp, query, gconf->dht_port, -1);
	} else if (sscanf(request, " announce%*[ ]%255[^: \n\t]:%d %c", query, &port, &d) == 2) {
		cmd_announce(fp, query, port, -1);
	} else if (sscanf(request, " announce%*[ ]%255[^: \n\t] %d %c", query, &minutes, &d) == 2) {
		cmd_announce(fp, query, -1, minutes);
	} else if (sscanf(request, " announce%*[ ]%255[^: \n\t]:%d %d %c", query, &port, &minutes, &d) == 3) {
		cmd_announce(fp, query, port, minutes);
	} else if (match(request, " list%*[ ]%*s %n") && allow_debug) {
		if (sscanf(request, "blacklist%*[ ]%255[^: \n\t]", query) == 1) {
			cmd_blacklist(fp, query);
		} else if (match(request, " list%*[ ]blacklist %n")) {
			kad_debug_blacklist(fp);
		} else if (match(request, " list%*[ ]constants %n")) {
			kad_debug_constants(fp);
		} else if (match(request, " list%*[ ]peers %n")) {
			if (kad_export_peers(fp) == 0) {
				fprintf(fp, "No good nodes found.\n");
			}
		} else if (match(request, " list%*[ ]searches %n")) {
			searches_debug(fp);
		} else if (match(request, " list%*[ ]announcements %n")) {
			announces_debug(fp);
		} else if (match(request, " list%*[ ]dht_buckets %n")) {
			kad_debug_buckets(fp);
		} else if (match(request, " list%*[ ]dht_searches %n")) {
			kad_debug_searches(fp);
		} else if (match(request, " list%*[ ]dht_storage %n")) {
			kad_debug_storage(fp);
		} else {
			fprintf(fp, "Unknown command.\n");
		}
	} else {
		// Print usage
		fprintf(fp, "%s", g_server_usage);

		if (allow_debug) {
			fprintf(fp, "%s", g_server_usage_debug);
		}
	}
}

static void cmd_client_handler(int rc, int clientsock)
{
	// save state since a line and come in multiple calls
	static char request[256];
	static ssize_t request_length = 0;
	static int current_clientsock = -1;
	static FILE* current_clientfd = NULL;

	if (rc <= 0) {
		return;
	}

	ssize_t remaining = sizeof(request) - request_length;
	ssize_t size = read(clientsock, &request[request_length], remaining);

	if (size == -1) {
		return;
	} else {
		request_length += size;
	}

	if (current_clientfd == NULL) {
		current_clientfd = fdopen(clientsock, "w");
	}

	if (request_length > 0 && size != 0) {
		// split lines
		char* beg = request;
		const char* end = request + request_length;
		char *cur = beg;
		while (true) {
			char *next = memchr(cur, '\n', end - cur);
			if (next) {
				*next = '\0'; // replace newline with 0
				#ifdef DEBUG
					cmd_exec(current_clientfd, cur, 1);
				#else
					cmd_exec(current_clientfd, cur, 0);
				#endif
				fflush(current_clientfd);
				cur = next + 1;

				// force connection to be
				// closed after one command
				size = 0;
			} else {
				break;
			}
		}

		// move unhandled data to the front of the buffer
		if (cur > beg) {
			memmove(beg, cur, cur - beg);
			request_length = end - cur;
			remaining = sizeof(request) - request_length;
		}
	}

	if (size == 0 || remaining == 0) {
		// socket closed
		if (current_clientfd) {
			fclose(current_clientfd);
		} else {
			close(current_clientsock);
		}

		current_clientsock = -1;
		current_clientfd = NULL;
		request_length = 0;

		net_remove_handler(clientsock, &cmd_client_handler);
	}
}

static void cmd_server_handler(int rc, int serversock)
{
	int clientsock;

	if (rc <= 0) {
		return;
	}

	clientsock = accept(serversock, NULL, NULL);
	if (clientsock < 0) {
		log_error("accept(): %s", strerror(errno));
		return;
	}

	net_add_handler(clientsock, &cmd_client_handler);
}

// special case for local console
static void cmd_console_handler(int rc, int fd)
{
	char request[256];
	char *ptr;

	if (rc <= 0) {
		return;
	}

	// Read line
	ptr = fgets(request, sizeof(request), stdin);
	if (ptr == NULL) {
		return;
	}

	// Output to stdout (not stdin)
	cmd_exec(stdout, request, 1);
}

int cmd_setup(void)
{
	if (EXIT_FAILURE == unix_create_unix_socket(gconf->cmd_path, &g_cmd_sock)) {
		return EXIT_FAILURE;
	} else {
		log_info("CMD: Bind to %s", gconf->cmd_path);

		net_add_handler(g_cmd_sock, &cmd_server_handler);

		if (!gconf->is_daemon && !gconf->cmd_disable_stdin) {
			fprintf(stdout, "Press Enter for help.\n");
			net_add_handler(STDIN_FILENO, &cmd_console_handler);
		}

		return EXIT_SUCCESS;
	}
}

void cmd_free(void)
{
	if (g_cmd_sock >= 0) {
		unix_remove_unix_socket(gconf->cmd_path, g_cmd_sock);
	}
}

#ifdef __CYGWIN__
static int select_read(int sockfd, char buffer[], int bufsize, struct timeval *tv)
{
	fd_set rfds;
	int retval;

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	retval = select(sockfd + 1, &rfds, NULL, NULL, tv);

	if (retval == -1) {
		// Error
		return -1;
	} else if (retval) {
		// Data available
		return read(sockfd, buffer, bufsize);
	} else {
		// Timeout reached
		return 0;
	}
}
#endif

int cmd_client(int argc, char *argv[])
{
	char buffer[256];
	const char *path;
	struct sockaddr_un addr = { 0 };
	ssize_t size;
	size_t all;
	size_t pos;
	int sock;
	int i;

	// Default unix socket path
	path = CMD_PATH;

	// Skip program name
	argc -= 1;
	argv += 1;

	if (argc >= 1) {
		if (strcmp(argv[0], "-h") == 0) {
			fprintf(stdout, "%s", g_client_usage);
			return EXIT_SUCCESS;
		} else if (strcmp(argv[0], "-p") == 0) {
			if (argc >= 2) {
				path = argv[1];
				// Skip option and path
				argc -= 2;
				argv += 2;
			} else {
				fprintf(stderr, "Path is missing!\n");
				return EXIT_FAILURE;
			}
		}
	}

	if (strlen(path) > FIELD_SIZEOF(struct sockaddr_un, sun_path) - 1) {
		fprintf(stderr, "Path too long!\n");
		return EXIT_FAILURE;
	}

	for (all = 0, i = 1; i < argc; i++) {
		all += strlen(argv[i]) + 1;
	}

	if (all >= sizeof(buffer)) {
		fprintf(stderr, "Input too long!\n");
		return EXIT_FAILURE;
	}

	// Concatenate arguments
	for (i = 0, pos = 0; i < argc; i++) {
		size_t len = strlen(argv[i]);
		//printf("add %s\n", argv[i]);
		memcpy(&buffer[pos], argv[i], len);
		pos += len;
		buffer[pos] = ' ';
		pos += 1;
	}
	buffer[pos] = '\n';
	pos += 1;

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket(): %s\n", strerror(errno));
		return EXIT_FAILURE;
	}

	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		fprintf(stderr, "Failed to connect to '%s': %s\n", path, strerror(errno));
		goto error;
	}

#ifdef __CYGWIN__
	struct timeval tv;

	/* Set receive timeout: 200ms */
	tv.tv_sec = 0;
	tv.tv_usec = 200000;

	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0) {
		fprintf(stderr, "setsockopt(): %s\n", strerror(errno));
		goto error;
	}
#endif

	// Write request
	size_t ret = write(sock, buffer, pos);

	if (ret < 0) {
		fprintf(stderr, "write(): %s\n", strerror(errno));
		goto error;
	}

	while (true) {
		// Receive replies
#ifdef __CYGWIN__
		size = select_read(sock, buffer, sizeof(buffer), &tv);
#else
		size = read(sock, buffer, sizeof(buffer));
#endif
		if (size == 0) {
			// socket closed
			break;
		} else if (size > 0) {
			// Print to console
			buffer[size] = 0;
			printf("%s", buffer);
		}
	}

	close(sock);

	return EXIT_SUCCESS;

error:
	if (sock > 0) {
		close(sock);
	}

	return EXIT_FAILURE;
}
