
#ifndef _MAIN_H_
#define _MAIN_H_


#include <netinet/in.h>

#define PROGRAM_NAME "DHTd"
#define PROGRAM_VERSION "0.2.6"

#define SHA1_BIN_LENGTH 20

// Default addresses and ports
#define LPD_ADDR4 "239.192.152.143"
#define LPD_ADDR6 "ff15::efc0:988f"
#define CLI_PATH "/tmp/dhtd.sock"
#define LPD_PORT 6771
#define DHT_PORT 6881

typedef struct sockaddr_storage IP;
typedef struct sockaddr_in IP4;
typedef struct sockaddr_in6 IP6;


void main_setup(void);
void main_free(void);


#endif // _MAIN_H_
