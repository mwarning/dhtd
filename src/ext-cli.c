
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
#include <ctype.h>

#include "main.h"
#include "conf.h"
#include "utils.h"
#include "log.h"
#include "kad.h"
#include "net.h"
#include "unix.h"
#include "announces.h"
#include "ext-cli.h"


static const char *g_client_usage =
PROGRAM_NAME" Control Program - Send commands to a DHTd instance.\n\n"
"Usage: dhtd-ctl [OPTIONS] [COMMANDS]\n"
"\n"
" -p <file>	Connect to this unix socket (Default: "CLI_PATH")\n"
" -h		Print this help.\n"
"\n";

static const char* g_server_usage =
	"Usage:\n"
	"	status\n"
	"	search [start|stop|results] <hash>\n"
	"	announce [start|stop] [<hash>[:<port>] [<minutes>]]\n"
	"	ping <address>\n"
	"	lookup <hash>\n";

const char* g_server_usage_debug =
	"	blacklist <address>\n"
	"	list announcements|searches|constants|blacklist\n"
	"	list peers|buckets|storage\n";

static int g_cli_sock = -1;


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

static bool cmd_announce(FILE *fp, const char hash[], const char *port_str, char *minutes_str)
{
	uint8_t id[SHA1_BIN_LENGTH];
	time_t lifetime;
	int minutes;
	int port;

	if (port_str) {
		port = parse_int(port_str, -1);
		if (!port_valid(port)) {
			fprintf(fp, "invalid port: %s\n", port_str);
			return false;
		}
	} else {
		port = gconf->dht_port;
	}

	if (minutes_str) {
		minutes = parse_int(minutes_str, -1);
		if (minutes < 0) {
			fprintf(fp, "invalid minutes: %s\n", minutes_str);
			return false;
		}
		// Round up to multiple of 30 minutes
		minutes = (30 * (minutes / 30 + 1));
		lifetime = (time_now_sec() + (minutes * 60));
	} else {
		lifetime = LONG_MAX;
	}

	if (!parse_hex_id(id, sizeof(id), hash, strlen(hash))) {
		fprintf(fp, "Invalid query: %s (no 20 byte hex string)\n", hash);
	} else if(announces_add(id, port, lifetime)) {
		if (minutes < 0) {
			fprintf(fp, "Start regular announcements for the entire run time (port %d).\n", port);
		} else {
			fprintf(fp, "Start regular announcements for %d minutes (port %d).\n", minutes, port);
		}
	} else {
		fprintf(fp, "Failed to add announcement.\n");
		return false;
	}

	return true;
}

// separate a string into a list of arguments (int argc, char **argv)
static int setargs(char **argv, int max_argv, char *args)
{
	int count = 0;

	while (isspace(*args)) {
		++args;
	}

	while (*args) {
		if (count < max_argv) {
			argv[count] = args;
		} else {
			log_error("too many arguments from command line");
			break;
		}

		while (*args && !isspace(*args)) {
			++args;
		}

		if (*args) {
			*args++ = '\0';
		}

		while (isspace(*args)) {
			++args;
		}

		count++;
	}

	argv[count] = NULL;
	return count;
}

static void cmd_exec(FILE *fp, char request[], bool allow_debug)
{
	uint8_t id[SHA1_BIN_LENGTH];
	char *argv[8];
	int argc = setargs(&argv[0], ARRAY_SIZE(argv), request);

	if (argc == 2 && !strcmp("ping", argv[0])) {
		const char *address = argv[1];
		int count = 0;

		if (gconf->af == AF_UNSPEC) {
			count += cmd_ping(fp, address, AF_INET);
			count += cmd_ping(fp, address, AF_INET6);
		} else {
			count += cmd_ping(fp, address, gconf->af);
		}

		if (count == 0) {
			fprintf(fp, "Failed to parse/resolve address.\n");
		}
	} else if (argc == 3 && !strcmp("search", argv[0])) {
		const char *cmd = argv[1];
		const char *id_str = argv[2];
		if (parse_hex_id(id, sizeof(id), id_str, strlen(id_str))) {
			if (!strcmp("start", cmd)) {
				kad_start_search(fp, id, 0);
			} else if (!strcmp("stop", cmd)) {
				kad_stop_search(fp, id);
			} else if (!strcmp("results", cmd)) {
				kad_print_results(fp, id);
			} else {
				fprintf(fp, "invalid search command\n");
			}
		} else {
			fprintf(fp, "Failed to parse id.\n");
		}
	} else if (argc == 2 && !strcmp("lookup", argv[0])) {
		const char *id_str = argv[1];
		
		if (parse_hex_id(id, sizeof(id), id_str, strlen(id_str))) {
			kad_print_node_addresses(fp, id);
		} else {
			fprintf(fp, "Failed to parse id.\n");
		}
	} else if (argc == 1 && !strcmp("status", argv[0])) {
		// Print node id and statistics
		kad_status(fp);
	} else if (argc > 1 && !strcmp("announce", argv[0])) {
		const char *cmd = argv[1];
		if ((argc == 3 || argc == 4) && !strcmp("start", cmd)) {
			// Announce specific value
			char *hash = argv[1];
			char *port = NULL;
			char *minutes = NULL;
			char *ptr = strchr(hash, ':');
			if (ptr) {
				*ptr = 0;
				port = ptr + 1; // jump past ':'
			}
			if (argc == 4) {
				minutes = argv[2];
			}
			cmd_announce(fp, hash, port, minutes);
		} else if (argc == 3 && !strcmp("stop", cmd)) {
			const char *id_str = argv[2];
			if (!parse_hex_id(id, sizeof(id), id_str, strlen(id_str))) {
				fprintf(fp, "Invalid query: %s (no 20 byte hex string)\n", id_str);
			} else {
				announcement_remove(id);
			}
		} else {
			fprintf(fp, "invalid announce command\n");
		}
	} else if (argc == 2 && !strcmp("blacklist", argv[0])) {
		IP address;
		if (addr_parse(&address, argv[1], NULL, gconf->af)) {
			kad_blacklist(&address);
			fprintf(fp, "Added to blacklist: %s\n", str_addr(&address));
		} else {
			fprintf(fp, "Invalid address.\n");
		}
	} else if (argc == 2 && !strcmp("list", argv[0])) {
		const char *cmd = argv[1];
		if (!strcmp("blacklist", cmd)) {
			kad_print_blacklist(fp);
		} else if (!strcmp("constants", cmd)) {
			kad_print_constants(fp);
		} else if (allow_debug && !strcmp("peers", cmd)) {
			kad_export_peers(fp);
		} else if (!strcmp("announcements", cmd)) {
			announces_debug(fp);
		} else if (allow_debug && !strcmp("buckets", cmd)) {
			kad_print_buckets(fp);
		} else if (!strcmp("searches", cmd)) {
			kad_print_searches(fp, false);
		} else if (allow_debug && !strcmp("storage", cmd)) {
			kad_print_storage(fp);
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

static void cli_client_handler(int rc, int clientsock)
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
					cmd_exec(current_clientfd, cur, true);
				#else
					cmd_exec(current_clientfd, cur, false);
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

		net_remove_handler(clientsock, &cli_client_handler);
	}
}

static void cli_server_handler(int rc, int serversock)
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

	net_add_handler(clientsock, &cli_client_handler);
}

// special case for local console
static void cli_console_handler(int rc, int fd)
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
	cmd_exec(stdout, request, true);
}

bool cli_setup(void)
{
	if (!unix_create_unix_socket(gconf->cli_path, &g_cli_sock)) {
		return false;
	} else {
		log_info("CLI: Bind to %s", gconf->cli_path);

		net_add_handler(g_cli_sock, &cli_server_handler);

		if (!gconf->is_daemon && !gconf->cli_disable_stdin) {
			fprintf(stdout, "Press Enter for help.\n");
			net_add_handler(STDIN_FILENO, &cli_console_handler);
		}

		return true;
	}
}

void cli_free(void)
{
	if (g_cli_sock >= 0) {
		unix_remove_unix_socket(gconf->cli_path, g_cli_sock);
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

int cli_client(int argc, char *argv[])
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
	path = CLI_PATH;

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
