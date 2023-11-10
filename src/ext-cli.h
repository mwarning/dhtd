
#ifndef _EXT_CLI_H_
#define _EXT_CLI_H_

// dhtd-ctl
int cli_client(int argc, char *argv[]);

// Start the remote console interface
bool cli_setup(void);
void cli_free(void);

#endif // _EXT_CLI_H_
