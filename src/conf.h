
#ifndef _CONF_H_
#define _CONF_H_

#include <time.h>
#include <stdbool.h>
#include "main.h"


extern const char *dhtd_version_str;

bool conf_setup(int argc, char **argv);
bool conf_load(void);
void conf_info(void);
void conf_free(void);


struct gconf_t {
	// Current time
	time_t time_now;

	// DHTd startup time
	time_t startup_time;

	// Drop privileges to user
	char *user;

	// Write a pid file if set
	char *pidfile;

	// Import/Export peers from this file
	char *peerfile;

	// Path to configuration file
	char *configfile;

	// Start in Foreground / Background
	bool is_daemon;

	// Thread terminator
	bool is_running;

	// Quiet / Verbose / Debug
	int verbosity;

	// Write log to /var/log/message
	bool use_syslog;

	// Net mode (AF_INET / AF_INET6 / AF_UNSPEC)
	int af;

	// DHT port number
	int dht_port;

	// DHT interface
	char *dht_ifname;

	// Script to execute on each new result
	char* execute_path;

#ifdef __CYGWIN__
	// Start as windows service
	bool service_start;
#endif

#ifdef LPD
	// Disable local peer discovery
	bool lpd_disable;
#endif

#ifdef CMD
	char *cmd_path;
	bool cmd_disable_stdin;
#endif
};

extern struct gconf_t *gconf;

#endif // _CONF_H_
