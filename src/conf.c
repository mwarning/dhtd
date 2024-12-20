
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
#include "announces.h"
#include "kad.h"
#ifdef __CYGWIN__
#include "windows.h"
#endif

// Global object variables
struct gconf_t *gconf = NULL;

static const char *g_announce_args[32] = { 0 };

const char *dhtd_version_str = PROGRAM_NAME " " PROGRAM_VERSION " ("
#ifdef CLI
" command-line-interface"
#endif
#ifdef DEBUG
" debug-build"
#endif
#ifdef LPD
" local-peer-discovery"
#endif
" )";

static const char *dhtd_usage_str =
"DHTd is a small DHT daemon.\n"
"\n"
"Usage: dhtd [OPTIONS]\n"
"\n"
" --announce <id>[:<port>}		Announce a id and optional port.\n"
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
" --lpd-disable				Disable local peer discovery.\n\n"
#endif
#ifdef CLI
" --cli-disable-stdin			Disable the local control interface.\n\n"
" --cli-path <path>			Bind the remote control interface to this unix socket path.\n"
"					Default: "CLI_PATH"\n\n"
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

#ifdef CLI
    free(gconf->cli_path);
#endif

    free(gconf);
}

// Enumerate all options to keep binary size smaller
enum {
    oAnnounce,
    oPidFile,
    oPeerFile,
    oPeer,
    oVerbosity,
    oCliDisableStdin,
    oCliPath,
    oConfig,
    oIpv4,
    oIpv6,
    oPort,
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

static const option_t g_options[] = {
    {"--announce", 1, oAnnounce},
    {"--pidfile", 1, oPidFile},
    {"--peerfile", 1, oPeerFile},
    {"--peer", 1, oPeer},
    {"--verbosity", 1, oVerbosity},
#ifdef CLI
    {"--cli-disable-stdin", 0, oCliDisableStdin},
    {"--cli-path", 1, oCliPath},
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

// Set a string once - error when already set
static bool conf_str(const char opt[], char *dst[], const char src[])
{
    if (*dst != NULL) {
        log_error("Value was already set for %s: %s", opt, src);
        return false;
    }

    *dst = strdup(src);
    return true;
}

static bool conf_port(const char opt[], int *dst, const char src[])
{
    int port = parse_int(src, -1);

    // port must be != 0
    if (!port_valid(port)) {
        log_error("Invalid port for %s: %s", opt, src);
        return false;
    }

    if (*dst >= 0) {
        log_error("Value was already set for %s: %s", opt, src);
        return false;
    }

    *dst = port;
    return true;
}

// forward declaration
static bool conf_set(const char opt[], const char val[]);

static bool conf_load_file(const char path[])
{
    char line[32 + 256];
    const char *argv[8];
    struct stat s;

    if (stat(path, &s) == 0 && !(s.st_mode & S_IFREG)) {
        log_error("File expected: %s", path);
        return false;
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        log_error("Cannot open file: %s (%s)", path, strerror(errno));
        return false;
    }

    ssize_t nline = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        nline += 1;

        // Cut off comments
        char *last = strchr(line, '#');
        if (last) {
            *last = '\0';
        }

        if (line[0] == '\n' || line[0] == '\0') {
            continue;
        }

        int argc = setargs(&argv[0], ARRAY_SIZE(argv), line);

        if (argc == 1 || argc == 2) {
            // Prevent recursive inclusion
            if (strcmp(argv[0], "--config") == 0) {
                fclose(file);
                log_error("Option '--config' not allowed inside a configuration file, line %ld.", nline);
                return false;
            }

            // parse --option value / --option
            if (!conf_set(argv[0], (argc == 2) ? argv[1] : NULL)) {
                fclose(file);
                return false;
            }
        } else {
            fclose(file);
            log_error("Invalid line in config file: %s (%d)", path, nline);
            return false;
        }
    }

    fclose(file);
    return true;
}

// Append to an array
static bool array_append(const char **array, size_t array_length, const char element[])
{
    size_t i = 0;

    while ((i < array_length) && (array[i] != NULL)) {
        i += 1;
    }

    if (i < array_length) {
        array[i] = strdup(element);
        return true;
    } else {
        return false;
    }
}

static bool conf_set(const char opt[], const char val[])
{
    const option_t *option = find_option(g_options, opt);

    if (option == NULL) {
        log_error("Unknown parameter: %s", opt);
        return false;
    }

    if (option->num_args == 1 && val == NULL) {
        log_error("Argument expected for %s", opt);
        return false;
    }

    if (option->num_args == 0 && val != NULL) {
        log_error("No argument expected for %s", opt);
        return false;
    }

    switch (option->code)
    {
    case oAnnounce:
        if (!is_announcement(val)) {
            log_error("Invalid announcement: %s", opt);
            return false;
        }
        if (!array_append(&g_announce_args[0], ARRAY_SIZE(g_announce_args), val)) {
            log_error("Too many announcements");
            return false;
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
            return false;
        }
        break;
#ifdef CLI
    case oCliDisableStdin:
        gconf->cli_disable_stdin = true;
        break;
    case oCliPath:
        if (strlen(val) > FIELD_SIZEOF(struct sockaddr_un, sun_path) - 1) {
            log_error("Path too long for %s", opt);
            return false;
        }
        return conf_str(opt, &gconf->cli_path, val);
#endif
    case oConfig:
        return conf_str(opt, &gconf->configfile, val);
    case oIpv4:
    case oIpv6:
        if (gconf->af != AF_UNSPEC) {
            log_error("IPv4 or IPv6 mode already set: %s", opt);
            return false;
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
        return false;
    }

    return true;
}

// Load some values that depend on proper settings
bool conf_load(void)
{
    uint8_t id[SHA1_BIN_LENGTH];
    int port;

    for (size_t i = 0; g_announce_args[i]; i += 1) {
        const char* arg = g_announce_args[i];

        if (parse_annoucement(id, &port, arg, gconf->dht_port)) {
            announces_add(NULL, id, port, LONG_MAX);
        } else {
            log_error("Invalid announcement: %s", arg);
            return false;
        }
    }

    return true;
}

static struct gconf_t *conf_alloc(void)
{
    time_t now = time(NULL);

    struct gconf_t *conf = (struct gconf_t*) calloc(1, sizeof(struct gconf_t));
    *conf = ((struct gconf_t) {
        .dht_port = DHT_PORT,
        .af = AF_UNSPEC,
#ifdef DEBUG
        .verbosity = VERBOSITY_DEBUG,
#else
        .verbosity = VERBOSITY_VERBOSE,
#endif
#ifdef CLI
        .cli_path = strdup(CLI_PATH),
#endif
        .time_now = now,
        .startup_time = now,
        .is_running = true
    });

    return conf;
}

bool conf_setup(int argc, char **argv)
{
    const char *opt;
    const char *val;

    gconf = conf_alloc();

    for (size_t i = 1; i < argc; ++i) {
        opt = argv[i];
        val = argv[i + 1];

        if (val && val[0] != '-') {
            // -x abc
            if (!conf_set(opt, val)) {
                return false;
            }
            i += 1;
        } else {
            // -x
            if (!conf_set(opt, NULL)) {
                return false;
            }
        }
    }

    if (gconf->configfile) {
        if (!conf_load_file(gconf->configfile)) {
            return false;
        }
    }

    return true;
}
