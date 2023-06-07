
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <getopt.h>

#include "main.h"
#include "log.h"
#include "utils.h"
#include "conf.h"
#include "peerfile.h"
#include "kad.h"
#ifdef __CYGWIN__
#include "windows.h"
#endif

// Global object variables
struct gconf_t *gconf = NULL;

static const char *g_announce_args[32] = { 0 };
static const char *g_search_args[32] = { 0 };

const char *dhtd_version_str = "DHTd v"MAIN_VERSION" ("
" cmd"
#ifdef DEBUG
" debug"
#endif
#ifdef LPD
" lpd"
#endif
" )";

static const char *dhtd_usage_str =
"DHTd is a small DHT daemon.\n"
"\n"
"Usage: dhtd [OPTIONS]\n"
"\n"
" --announce <name>:<port>		Announce a hash and port.\n"
"					This option may occur multiple times.\n\n"
" --peerfile <file>			Import/Export peers from and to a file.\n\n"
" --peer <address>			Add a static peer address.\n"
"					This option may occur multiple times.\n\n"
" --execute <file>			Execute a script for each result.\n\n"
" --port	<port>				Bind DHT to this port.\n"
"					Default: "STR(DHT_PORT)"\n\n"
" --config <file>			Provide a configuration file with one command line\n"
"					option on each line. Comments start after '#'.\n\n"
" --ifname <interface>			Bind to this interface.\n"
"					Default: <any>\n\n"
" --daemon, -d				Run the node in background.\n\n"
" --verbosity <level>			Verbosity level: quiet, verbose or debug.\n"
"					Default: verbose\n\n"
" --user <user>				Change the UUID after start.\n\n"
" --pidfile <file>			Write process pid to a file.\n\n"
" --ipv4, -4, --ipv6, -6			Enable IPv4 or IPv6 only mode.\n"
"					Default: IPv4+IPv6\n\n"
#ifdef LPD
" --lpd-disable				Disable multicast to discover local peers.\n\n"
#endif
#ifdef CMD
" --cmd-disable-stdin			Disable the local control interface.\n\n"
" --cmd-path <path>			Bind the remote control interface to this unix socket path.\n"
"					Default: "CMD_PATH"\n\n"
#endif
#ifdef __CYGWIN__
" --service-start			Start, install and remove DHTd as Windows service.\n"
" --service-install			DHTd will be started/shut down along with Windows\n"
" --service-remove			or on request by using the Service Control Manager.\n\n"
#endif
" --help, -h				Print this help.\n\n"
" --version, -v				Print program version.\n";


const char *verbosity_str(int verbosity)
{
	switch (verbosity) {
	case VERBOSITY_QUIET: return "quiet";
	case VERBOSITY_VERBOSE: return "verbose";
	case VERBOSITY_DEBUG: return "debug";
	default:
		log_error("Invalid verbosity: %d", verbosity);
		exit(1);
	}
}

void conf_info(void)
{
	log_info("Starting %s", dhtd_version_str);
	log_info("Net Mode: %s", str_af(gconf->af));
	log_info("Run Mode: %s", gconf->is_daemon ? "daemon" : "foreground");

	if (gconf->configfile) {
		log_info("Configuration File: %s", gconf->configfile);
	}

	log_info("Verbosity: %s", verbosity_str(gconf->verbosity));
	log_info("Peer File: %s", gconf->peerfile ? gconf->peerfile : "none");
#ifdef LPD
	log_info("Local Peer Discovery: %s", gconf->lpd_disable ? "disabled" : "enabled");
#endif
}

void conf_free(void)
{
	free(gconf->user);
	free(gconf->pidfile);
	free(gconf->peerfile);
	free(gconf->dht_ifname);
	free(gconf->configfile);

#ifdef CMD
	free(gconf->cmd_path);
#endif

	free(gconf);
}

// Enumerate all options to keep binary size smaller
enum OPCODE {
	oAnnounce,
	oPidFile,
	oPeerFile,
	oPeer,
	oVerbosity,
	oCmdDisableStdin,
	oCmdPath,
	oConfig,
	oIpv4,
	oIpv6,
	oPort,
	oSearch,
	oLpdDisable,
	oServiceInstall,
	oServiceRemove,
	oServiceStart,
	oIfname,
	oExecute,
	oUser,
	oDaemon,
	oHelp,
	oVersion
};

struct option_t {
	const char *name;
	uint16_t num_args;
	uint16_t code;
};

static struct option_t g_options[] = {
	{"--announce", 1, oAnnounce},
	{"--search", 1, oSearch},
	{"--pidfile", 1, oPidFile},
	{"--peerfile", 1, oPeerFile},
	{"--peer", 1, oPeer},
	{"--verbosity", 1, oVerbosity},
#ifdef CMD
	{"--cmd-disable-stdin", 0, oCmdDisableStdin},
	{"--cmd-path", 1, oCmdPath},
#endif
	{"--config", 1, oConfig},
	{"--port", 1, oPort},
	{"-4", 0, oIpv4},
	{"--ipv4", 0, oIpv4},
	{"-6", 0, oIpv6},
	{"--ipv6", 0, oIpv6},
#ifdef LPD
	{"--lpd-disable", 0, oLpdDisable},
#endif
#ifdef __CYGWIN__
	{"--service-install", 0, oServiceInstall},
	{"--service-remove", 0, oServiceRemove},
	{"--service-start", 0, oServiceStart},
#endif
	{"--ifname", 1, oIfname},
	{"--execute", 1, oExecute},
	{"--user", 1, oUser},
	{"--daemon", 0, oDaemon},
	{"-d", 0, oDaemon},
	{"-h", 0, oHelp},
	{"--help", 0, oHelp},
	{"-v", 0, oVersion},
	{"--version", 0, oVersion},
	{NULL, 0, 0}
};

static const struct option_t *find_option(const char name[])
{
	struct option_t *option;

	option = g_options;
	while (option->name) {
		if (0 == strcmp(name, option->name)) {
			return option;
		}
		option++;
	}

	return NULL;
}

// Set a string once - error when already set
static int conf_str(const char opt[], char *dst[], const char src[])
{
	if (*dst != NULL) {
		log_error("Value was already set for %s: %s", opt, src);
		return EXIT_FAILURE;
	}

	*dst = strdup(src);
	return EXIT_SUCCESS;
}

static int conf_port(const char opt[], int *dst, const char src[])
{
	int n = port_parse(src, -1);

	if (n < 0) {
		log_error("Invalid port for %s: %s", opt, src);
		return EXIT_FAILURE;
	}

	if (*dst >= 0) {
		log_error("Value was already set for %s: %s", opt, src);
		return EXIT_FAILURE;
	}

	*dst = n;
	return EXIT_SUCCESS;
}

// forward declaration
static int conf_set(const char opt[], const char val[]);

static int conf_load_file(const char path[])
{
	char option[32];
	char value[256];
	char line[32 + 256];
	char dummy[4];
	char *last;
	struct stat s;
	int ret;
	FILE *file;
	size_t nline;

	if (stat(path, &s) == 0 && !(s.st_mode & S_IFREG)) {
		log_error("File expected: %s", path);
		return EXIT_FAILURE;
	}

	nline = 0;
	file = fopen(path, "r");
	if (file == NULL) {
		log_error("Cannot open file: %s (%s)", path, strerror(errno));
		return EXIT_FAILURE;
	}

	while (fgets(line, sizeof(line), file) != NULL) {
		nline += 1;

		// Cut off comments
		last = strchr(line, '#');
		if (last) {
			*last = '\0';
		}

		if (line[0] == '\n' || line[0] == '\0') {
			continue;
		}

		ret = sscanf(line, " %31s%*[ ]%255s %3s", option, value, dummy);

		if (ret == 1 || ret == 2) {
			// Prevent recursive inclusion
			if (strcmp(option, "--config ") == 0) {
				fclose(file);
				log_error("Option '--config' not allowed inside a configuration file, line %ld.", nline);
				return EXIT_FAILURE;
			}

			// parse --option value / --option
			ret = conf_set(option, (ret == 2) ? value : NULL);
			if (ret == EXIT_FAILURE) {
				fclose(file);
				return EXIT_FAILURE;
			}
		} else {
			fclose(file);
			log_error("Invalid line in config file: %s (%d)", path, nline);
			return EXIT_FAILURE;
		}
	}

	fclose(file);
	return EXIT_SUCCESS;
}

// Append to an array (assumes there is alway enough space ...)
static int array_append(const char **array, size_t array_length, const char element[])
{
	size_t i = 0;

	while ((i < array_length) && (array != NULL)) {
		i += 1;
	}

	if (i < array_length) {
		array[i] = strdup(element);
		return EXIT_SUCCESS;
	} else {
		return EXIT_FAILURE;
	}
}

static int conf_set(const char opt[], const char val[])
{
	const struct option_t *option;

	option = find_option(opt);

	if (option == NULL) {
		log_error("Unknown parameter: %s", opt);
		return EXIT_FAILURE;
	}

	if (option->num_args == 1 && val == NULL) {
		log_error("Argument expected for option: %s", opt);
		return EXIT_FAILURE;
	}

	if (option->num_args == 0 && val != NULL) {
		log_error("No argument expected for option: %s", opt);
		return EXIT_FAILURE;
	}

	switch (option->code)
	{
	case oAnnounce:
		if (!is_hex_id(val)) {
			log_error("Invalid announce hash: %s", opt);
			return EXIT_FAILURE;
		}
		if (EXIT_FAILURE == array_append(&g_announce_args[0], ARRAY_SIZE(g_announce_args), val)) {
			log_error("Too many announce entries");
			return EXIT_FAILURE;
		}
		break;
	case oSearch:
		if (!is_hex_id(val)) {
			log_error("Invalid search hash: %s", opt);
			return EXIT_FAILURE;
		}
		if (EXIT_FAILURE == array_append(&g_search_args[0], ARRAY_SIZE(g_search_args), val)) {
			log_error("Too many search entries");
			return EXIT_FAILURE;
		}
		break;
	case oPidFile:
		return conf_str(opt, &gconf->pidfile, val);
	case oPeerFile:
		return conf_str(opt, &gconf->peerfile, val);
	case oPeer:
		return peerfile_add_peer(val);
	case oVerbosity:
		if (strcmp(val, "quiet") == 0) {
			gconf->verbosity = VERBOSITY_QUIET;
		} else if (strcmp(val, "verbose") == 0) {
			gconf->verbosity = VERBOSITY_VERBOSE;
		} else if (strcmp(val, "debug") == 0) {
			gconf->verbosity = VERBOSITY_DEBUG;
		} else {
			log_error("Invalid argument for %s", opt);
			return EXIT_FAILURE;
		}
		break;
#ifdef CMD
	case oCmdDisableStdin:
		gconf->cmd_disable_stdin = true;
		break;
	case oCmdPath:
		if (strlen(val) > FIELD_SIZEOF(struct sockaddr_un, sun_path) - 1) {
			log_error("Path too long for %s", opt);
			return EXIT_FAILURE;
		}
		return conf_str(opt, &gconf->cmd_path, val);
#endif
	case oConfig:
		return conf_str(opt, &gconf->configfile, val);
	case oIpv4:
	case oIpv6:
		if (gconf->af != AF_UNSPEC) {
			log_error("IPv4 or IPv6 mode already set: %s", opt);
			return EXIT_FAILURE;
		}

		gconf->af = (option->code == oIpv6) ? AF_INET6 : AF_INET;
		break;
	case oPort:
		return conf_port(opt, &gconf->dht_port, val);
#ifdef LPD
	case oLpdDisable:
		gconf->lpd_disable = true;
		break;
#endif
#ifdef __CYGWIN__
	case oServiceInstall:
		windows_service_install();
		exit(0);
	case oServiceRemove:
		windows_service_remove();
		exit(0);
	case oServiceStart:
		gconf->service_start = true;
		break;
#endif
	case oIfname:
		return conf_str(opt, &gconf->dht_ifname, val);
	case oExecute:
		return conf_str(opt, &gconf->execute_path, val);
	case oUser:
		return conf_str(opt, &gconf->user, val);
	case oDaemon:
		gconf->is_daemon = true;
		break;
	case oHelp:
		printf("%s\n", dhtd_usage_str);
		exit(0);
	case oVersion:
		printf("%s\n", dhtd_version_str);
		exit(0);
	default:
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

// Load some values that depend on proper settings
int conf_load(void)
{
	for (size_t i = 0; g_announce_args[i]; i += 1) {
		const char* arg = g_announce_args[i];
		uint16_t port = gconf->dht_port;
		char query[QUERY_MAX_SIZE] = { 0 };

		int n = sscanf(arg, "%254[^:]:%hu", query, &port);
		if (n == 1 || n == 2) {
			kad_announce(query, port, LONG_MAX);
		} else {
			log_error("Invalid announcement: %s", arg);
		}
	}

	for (size_t i = 0; g_search_args[i]; i += 1) {
		const char* arg = g_search_args[i];

		if (is_hex_id(arg)) {
			kad_search(arg);
		} else {
			log_error("Invalid search hash: %s", arg);
		}
	}

	return EXIT_SUCCESS;
}

static struct gconf_t *conf_alloc()
{
	struct gconf_t *conf;
	time_t now = time(NULL);

	conf = (struct gconf_t*) calloc(1, sizeof(struct gconf_t));
	*conf = ((struct gconf_t) {
		.dht_port = DHT_PORT,
		.af = AF_UNSPEC,
#ifdef DEBUG
		.verbosity = VERBOSITY_DEBUG,
#else
		.verbosity = VERBOSITY_VERBOSE,
#endif
#ifdef CMD
		.cmd_path = strdup(CMD_PATH),
#endif
		.time_now = now,
		.startup_time = now,
		.is_running = true
	});

	return conf;
}

int conf_setup(int argc, char **argv)
{
	const char *opt;
	const char *val;
	int rc;
	int i;

	gconf = conf_alloc();

	for (i = 1; i < argc; ++i) {
		opt = argv[i];
		val = argv[i + 1];

		if (val && val[0] != '-') {
			// -x abc
			rc = conf_set(opt, val);
			i += 1;
		} else {
			// -x
			rc = conf_set(opt, NULL);
		}

		if (rc == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
	}

	if (gconf->configfile) {
		rc = conf_load_file(gconf->configfile);

		if (rc == EXIT_FAILURE) {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
