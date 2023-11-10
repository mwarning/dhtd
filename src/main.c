#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#ifdef __CYGWIN__
#include <windows.h>
#endif

#include "main.h"
#include "conf.h"
#include "log.h"
#include "kad.h"
#include "utils.h"
#include "unix.h"
#include "net.h"
#include "announces.h"
#include "peerfile.h"
#ifdef __CYGWIN__
#include "windows.h"
#endif

#ifdef LPD
#include "ext-lpd.h"
#endif
#include "ext-cli.h"

static bool g_pidfile_written = false;


int main_run(void)
{
	bool rc = true;

	/* Run setup */
	if (!conf_load()) {
		return EXIT_FAILURE;
	}

	// Setup the Kademlia DHT
	rc &= kad_setup();

	// Setup handler for announcements
	announces_setup();

	// Setup import of peerfile
	peerfile_setup();

	// Setup extensions
#ifdef LPD
	rc &= lpd_setup();
#endif

#ifdef CLI
	rc &= cli_setup();
#endif

	/* Run program */
	if (rc) {
		// Loop over all sockets and file descriptors
		net_loop();
		log_info("Shutting down...");
	}

	// Export peers if a file is provided
	peerfile_export();

	/* Free resources */

#ifdef CLI
	cli_free();
#endif
#ifdef LPD
	lpd_free();
#endif

	peerfile_free();

	announces_free();

	kad_free();

	conf_free();

	net_free();

	if (g_pidfile_written) {
		unlink(gconf->pidfile);
	}

	return rc ? EXIT_SUCCESS : EXIT_FAILURE;
}

#ifdef __CYGWIN__
int main(int argc, char *argv[])
{
	char cmd[512];
	char path[256];
	char *p;

#ifdef CLI
	if (strstr(argv[0], "dhtd-ctl")) {
		return cli_client(argc, argv);
	}
#endif

	if (!conf_setup(argc, argv)) {
		return EXIT_FAILURE;
	}

	if (gconf->service_start) {
		gconf->use_syslog = true;

		// Get dhtd.exe binary lcoation
		if (GetModuleFileNameA(NULL, path, sizeof(path)) && (p = strrchr(path, '\\'))) {
			*(p + 1) = '\0';
		} else {
			log_error("Cannot get location of dhtd binary.");
			exit(1);
		}

		// Set DNS server to localhost
		sprintf(cmd, "cmd.exe /c \"%s\\dns_setup.bat\"", path);
		windows_exec(cmd);

		int rc = windows_service_start((void (*)()) main_run);

		// Reset DNS settings to DHCP
		sprintf(cmd, "cmd.exe /c \"%s\\dns_reset.bat\"", path);
		windows_exec(cmd);

		return rc;
	}

	if (gconf->is_daemon) {
		gconf->use_syslog = true;

		// Close pipes
		fclose(stderr);
		fclose(stdout);
		fclose(stdin);

		// Fork before any threads are started
		unix_fork();

		// Change working directory to C:\ directory or disk equivalent
		if (GetModuleFileNameA(NULL, path, sizeof(path)) && (p = strchr(path, '\\'))) {
			*(p + 1) = 0;
			SetCurrentDirectoryA(path);
		}

	} else {
		conf_info();
	}

	// Catch signals
	windows_signals();

	// Write pid file
	if (gconf->pidfile) {
		unix_write_pidfile(GetCurrentProcessId(), gconf->pidfile);
		g_pidfile_written = true;
	}

	// Drop privileges
	unix_dropuid0();

	return main_run();
}
#else
int main(int argc, char *argv[])
{
	if (strstr(argv[0], "dhtd-ctl")) {
		return cli_client(argc, argv);
	}

	if (!conf_setup(argc, argv)) {
		return EXIT_FAILURE;
	}

	if (gconf->is_daemon) {
		gconf->use_syslog = true;

		// Close pipes
		fclose(stderr);
		fclose(stdout);
		fclose(stdin);

		// Fork before any threads are started
		unix_fork();

		if (chdir("/") != 0) {
			log_error("Changing working directory to '/' failed: %s", strerror(errno));
			exit(1);
		}
	} else {
		conf_info();
	}

	// Catch signals
	unix_signals();

	// Write pid file
	if (gconf->pidfile) {
		unix_write_pidfile(getpid(), gconf->pidfile);
		g_pidfile_written = true;
	}

	// Drop privileges
	unix_dropuid0();

	return main_run();
}
#endif
