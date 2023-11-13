
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
#include "results.h"
#include "announces.h"
#include "ext-cli.h"


static const char *g_client_usage =
PROGRAM_NAME" Control Program - Send commands to a DHTd instance.\n\n"
"Usage: dhtd-ctl [OPTIONS] [COMMANDS]\n"
"\n"
" -p <file> Connect to this unix socket (Default: "CLI_PATH")\n"
" -h        Print this help.\n"
"\n";

static const char* g_server_usage =
	"Usage:\n"
	"  status\n"
	"  help\n"
	"  query\n"
	"  search <id>\n"
	"  results <id>\n"
	"  announce-start <id> <port>\n"
	"  announce-stop <id>\n"
	"  searches\n"
	"  announcements\n"
	"  block <address>\n"
	"  peer <address>\n"
	"  constants|blocklist|peers|buckets|storage\n";

static const char* g_server_help = 
	"  DHTd allows to search for peers that have announced a identifier.\n"
	"  The result is a list of IP addresses and ports of those peers that\n"
	"  have announcement it. DHTd also allows to perform announcements.\n"
	"\n"
	"  status\n"
	"    The current state of this node.\n"
	"  search <id>\n"
	"    Start a search for announced values.\n"
	"  results <id>\n"
	"    Print the results of a search.\n"
	"  query <id>\n"
	"    Start search and print results.\n"
	"  announce-start <id>[:<port>]\n"
	"    Start to announce an id along with a network port.\n"
	"  announce-stop <id>\n"
	"    Stop the announcement.\n"
	"  searches\n"
	"    Print a list of all searches. They expire after 20min.\n"
	"  announcements\n"
	"    Print a list of all announcements."
	"  peer <address>:<port>\n"
	"    Add a peer by address.\n"
	"  block <address>\n"
	"    Block a certain IP address for some time.\n"
	"  constants|blocklist|peers|buckets|storage\n"
	"    Print various internal data.\n"
	" -----\n"
	"  id: 20 bytes as base16 (hexadecimal) or base32 string\n"
	"  port: Network number between 1-65536\n"
	"  address: IPv4 or IPv6 address\n"
	"";

static int g_cli_sock = -1;


static int cmd_peer(FILE *fp, const char addr_str[], int af)
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

enum {
	oHelp,
	oPeer,
	oSearch,
	oResults,
	oQuery,
	oStatus,
	oAnnounceStart,
	oAnnounceStop,
	oPrintBlocked,
	oBlock,
	oPrintConstants,
	oPrintPeers,
	oPrintAnnouncements,
	oPrintBuckets,
	oPrintSearches,
	oPrintStorage
};

static const option_t g_options[] = {
	{"h", 1, oHelp},
	{"help", 1, oHelp},
	{"peer", 2, oPeer},
	{"search", 2, oSearch},
	{"results", 2, oResults},
	{"query", 2, oQuery},
	{"status", 1, oStatus},
	{"announce-start", 2, oAnnounceStart},
	{"announce-stop", 2, oAnnounceStop},
	{"block", 2, oBlock},
	{"blocklist", 1, oPrintBlocked},
	{"constants", 1, oPrintConstants},
	{"peers", 1, oPrintPeers},
	{"announcements", 1, oPrintAnnouncements},
	{"buckets", 1, oPrintBuckets},
	{"searches", 1, oPrintSearches},
	{"storage", 1, oPrintStorage},
	{NULL, 0, 0}
};

static void cmd_exec(FILE *fp, char request[], bool allow_debug)
{
	uint8_t id[SHA1_BIN_LENGTH];
	char *argv[8];
	int argc = setargs(&argv[0], ARRAY_SIZE(argv), request);

	if (argc == 0) {
		// Print usage
		fprintf(fp, "%s", g_server_usage);
		return;
	}

	const option_t *option = find_option(g_options, argv[0]);

	if (option == NULL) {
		fprintf(fp, "Unknown command.\n");
		return;
	}

	if (option->num_args != argc) {
		fprintf(fp, "Unexpected number of arguments.\n");
		return;
	}

	// parse identifier
	switch (option->code) {
		case oSearch: case oResults: case oQuery: case oBlock: case oAnnounceStop:
		if (!parse_id(id, sizeof(id), argv[1], strlen(argv[1]))) {
			fprintf(fp, "Failed to parse identifier.\n");
			return;
		}
	}

	switch (option->code) {
	case oHelp:
		fprintf(fp, "%s", g_server_help);
		break;
	case oPeer: {
		const char *address = argv[1];
		int count = 0;

		if (gconf->af == AF_UNSPEC) {
			count += cmd_peer(fp, address, AF_INET);
			count += cmd_peer(fp, address, AF_INET6);
		} else {
			count += cmd_peer(fp, address, gconf->af);
		}

		if (count == 0) {
			fprintf(fp, "Failed to parse/resolve address.\n");
		}
		break;
	}
	case oQuery:
		kad_start_search(NULL, id, 0);
		results_print(fp, id);
		break;
	case oSearch:
		kad_start_search(fp, id, 0);
		break;
	case oResults:
		results_print(fp, id);
		break;
	case oStatus:
		kad_status(fp);
		break;
	case oAnnounceStart: {
		int port;
		if (parse_annoucement(&id[0], &port, argv[1], gconf->dht_port)) {
			announces_add(fp, id, port, LONG_MAX);
		} else {
			fprintf(fp, "Invalid port: %s\n", argv[2]);
		}
		break;
	}
	case oAnnounceStop:
		announcement_remove(id);
		break;
	case oBlock: {
		IP address;
		if (addr_parse(&address, argv[1], NULL, gconf->af)) {
			kad_block(&address);
			fprintf(fp, "Added to blocklist: %s\n", str_addr(&address));
		} else {
			fprintf(fp, "Invalid address.\n");
		}
	}
	case oPrintSearches:
		kad_print_searches(fp);
		break;
	case oPrintAnnouncements:
		announces_print(fp);
		break;
	case oPrintBlocked:
		kad_print_blocklist(fp);
		break;
	case oPrintConstants:
		kad_print_constants(fp);
		break;
	case oPrintPeers:
		kad_export_peers(fp);
		break;
	case oPrintBuckets:
		kad_print_buckets(fp);
		break;
	case oPrintStorage:
		kad_print_storage(fp);
		break;
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
	if (rc <= 0) {
		return;
	}

	int clientsock = accept(serversock, NULL, NULL);
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

	if (rc <= 0) {
		return;
	}

	// Read line
	char *ptr = fgets(request, sizeof(request), stdin);
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

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	int retval = select(sockfd + 1, &rfds, NULL, NULL, tv);

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
	char buffer[1024];
	struct sockaddr_un addr = { 0 };

	// Default unix socket path
	const char *path = CLI_PATH;

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

	if (strlen(path) >= FIELD_SIZEOF(struct sockaddr_un, sun_path)) {
		fprintf(stderr, "Path too long!\n");
		return EXIT_FAILURE;
	}

	size_t pos = 0;
	if (!isatty(fileno(stdin))) {
		while(-1 != (buffer[pos++] = getchar()));
		pos--;
		if (buffer[pos-1] != '\n') {
			// Append newline if not present
			buffer[pos++] = '\n';
		}
	} else {
		// Concatenate arguments
		for (size_t i = 0; i < argc; i++) {
			size_t len = strlen(argv[i]);
			if ((pos + len + 1) >= sizeof(buffer)) {
				fprintf(stderr, "Input too long!\n");
				return EXIT_FAILURE;
			}
			memcpy(&buffer[pos], argv[i], len);
			pos += len;
			buffer[pos++] = ' ';
		}
		// Append newline
		buffer[pos++] = '\n';
	}

	int sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "socket() %s\n", strerror(errno));
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
		fprintf(stderr, "setsockopt() %s\n", strerror(errno));
		goto error;
	}
#endif

	// Write request
	size_t ret = write(sock, buffer, pos);

	if (ret < 0) {
		fprintf(stderr, "write() %s\n", strerror(errno));
		goto error;
	}

	while (true) {
		// Receive replies
#ifdef __CYGWIN__
		ssize_t size = select_read(sock, buffer, sizeof(buffer), &tv);
#else
		ssize_t size = read(sock, buffer, sizeof(buffer));
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
