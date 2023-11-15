
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "net.h"
#include "kad.h"
#include "ext-lpd.h"

/*
* Local Peer Discovery
*/

#ifdef __CYGWIN__
#ifndef AF_PACKET
#define AF_PACKET 17
#endif
#endif

enum {
	// Packets per minute to be handled
	PACKET_LIMIT_MAX = 20,
	// Limit multicast message to the same subnet
	TTL_SAME_SUBNET = 1
};

struct lpd_state {
	IP mcast_addr;
	time_t mcast_time;
	int packet_limit;
	int sock_send;
	int sock_listen;
};

struct lpd_state g_lpd4 = {
	.mcast_addr = {0},
	.mcast_time = 0,
	.packet_limit = PACKET_LIMIT_MAX,
	.sock_send = -1,
	.sock_listen = -1
};

struct lpd_state g_lpd6 = {
	.mcast_addr = {0},
	.mcast_time = 0,
	.packet_limit = PACKET_LIMIT_MAX,
	.sock_send = -1,
	.sock_listen = -1
};

static bool filter_ifa(const struct ifaddrs *ifa)
{
	if ((ifa->ifa_addr == NULL)
			|| !(ifa->ifa_flags & IFF_RUNNING)
			|| (ifa->ifa_flags & IFF_LOOPBACK)) {
		return false;
	}

	// if DHT interface set, use only that interface (if it exists)
	if (gconf->dht_ifname) {
		return (0 == strcmp(gconf->dht_ifname, ifa->ifa_name));
	} else {
		return true;
	}
}

static void join_mcast(const struct lpd_state* lpd, const struct ifaddrs *ifas)
{
	const char *prev_ifname = NULL;
	int family = lpd->mcast_addr.ss_family;

	for (const struct ifaddrs *ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		int ifa_family = ifa->ifa_addr->sa_family;

		if (!filter_ifa(ifa) || family != ifa_family) {
			continue;
		}

		if (ifa_family == AF_INET) {
			struct ip_mreq mcastReq = {0};

			mcastReq.imr_multiaddr = ((IP4*) &lpd->mcast_addr)->sin_addr;
			mcastReq.imr_interface.s_addr = htonl(INADDR_ANY);

			// ignore error (we might already be subscribed)
			if (setsockopt(lpd->sock_listen, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void const*)&mcastReq, sizeof(mcastReq)) < 0) {
				log_error("LPD: failed to join IPv4 multicast group: %s", strerror(errno));
			}
		} else { // AF_INET6
			// skip previous interface (relies on order of ifas)
			if (prev_ifname && 0 == strcmp(prev_ifname, ifa->ifa_name)) {
				continue;
			} else {
				prev_ifname = ifa->ifa_name;
			}

			unsigned ifindex = if_nametoindex(ifa->ifa_name);
			struct ipv6_mreq mreq6 = {0};

			memcpy(&mreq6.ipv6mr_multiaddr, &((IP6*) &lpd->mcast_addr)->sin6_addr, 16);
			mreq6.ipv6mr_interface = ifindex;

			// ignore error (we might already be subscribed)
			if (setsockopt(lpd->sock_listen, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0) {
				log_error("LPD: failed to join IPv6 multicast group: %s", strerror(errno));
			}
		}
	}
}

static void send_mcasts(const struct lpd_state* lpd, const struct ifaddrs *ifas)
{
	char message[16];

	sprintf(message, "DHT %d", gconf->dht_port);

	int family = lpd->mcast_addr.ss_family;
	const char *prev_ifname = NULL;

	for (const struct ifaddrs *ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		int ifa_family = ifa->ifa_addr->sa_family;

		if (!filter_ifa(ifa) || family != ifa_family) {
			continue;
		}

		if (ifa_family == AF_INET) {
			struct in_addr addr = ((struct sockaddr_in*) ifa->ifa_addr)->sin_addr;

			if (setsockopt(lpd->sock_send, IPPROTO_IP, IP_MULTICAST_IF, &addr, sizeof(addr)) < 0) {
				log_error("setsockopt(IP_MULTICAST_IF) %s %s", ifa->ifa_name, strerror(errno));
				continue;
			}
		} else { // AF_INET6
			// skip previous interface (relies on order of ifas)
			if (prev_ifname && 0 == strcmp(prev_ifname, ifa->ifa_name)) {
				continue;
			} else {
				prev_ifname = ifa->ifa_name;
			}

			unsigned ifindex = if_nametoindex(ifa->ifa_name);
			if (setsockopt(lpd->sock_send, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
				log_error("setsockopt(IPV6_MULTICAST_IF) %s %s", ifa->ifa_name, strerror(errno));
				continue;
			}
		}

		sendto(lpd->sock_send, (void const*) message, strlen(message), 0,
				(struct sockaddr const*) &lpd->mcast_addr, addr_len(&lpd->mcast_addr));

		log_debug("LPD: Send discovery message to %s on %s", str_addr(&lpd->mcast_addr), ifa->ifa_name);
	}
}

static void handle_mcast(int mcast_rc, struct lpd_state* lpd)
{
	// called at least every second
	if (lpd->mcast_time <= time_now_sec()) {
		struct ifaddrs *ifaddrs;
		if (getifaddrs(&ifaddrs) == 0) {
			// join multicast group (in case of new interfaces)
			join_mcast(lpd, ifaddrs);

			// No peers known, send multicast
			if (kad_count_nodes(false) == 0) {
				send_mcasts(lpd, ifaddrs);
			}
			freeifaddrs(ifaddrs);
		} else {
			log_error("getifaddrs() %s", strerror(errno));
		}

		// Cap number of received packets to 10 per minute
		lpd->packet_limit = 5 * PACKET_LIMIT_MAX;

		// Try again in ~5 minutes
		lpd->mcast_time = time_add_mins(5);
	}

	if (mcast_rc <= 0) {
		return;
	}

	// Receive multicast ping
	socklen_t addrlen = sizeof(IP);
	IP address = {0};
	char buf[16];
	int rc = recvfrom(lpd->sock_listen, buf, sizeof(buf) - 1, 0, (struct sockaddr*) &address, (socklen_t*) &addrlen);
	if (rc <= 0) {
		log_warning("LPD: Cannot receive multicast message: %s", strerror(errno));
		return;
	} else if (lpd->packet_limit < 0) {
		// Too much traffic
		return;
	} else {
		lpd->packet_limit -= 1;
	}

	buf[rc] = '\0';

	if (0 == strncmp(buf, "DHT ", 4)) {
		int port = parse_int(&buf[4], -1);
		if (port_valid(port)) {
			port_set(&address, port);
			log_debug("LPD: Ping lonely peer at %s", str_addr(&address));
			kad_ping(&address);
		}
	}
}

static void handle_mcast4(int rc, int sock)
{
	assert(sock == g_lpd4.sock_listen);
	handle_mcast(rc, &g_lpd4);
}

static void handle_mcast6(int rc, int sock)
{
	assert(sock == g_lpd6.sock_listen);
	handle_mcast(rc, &g_lpd6);
}

static int create_send_socket(int af)
{
	const int scope = TTL_SAME_SUBNET;
	const int opt_off = 0;

	int sock = net_socket("LPD", NULL, IPPROTO_IP, af);
	if (sock < 0) {
		return -1;
	}

	if (af == AF_INET) {
		in_addr_t iface = INADDR_ANY;

		// IPv4
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void const*)&scope, sizeof(scope)) != 0) {
			goto fail;
		}

		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char*)&iface, sizeof(iface)) != 0) {
			goto fail;
		}

		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off)) != 0) {
			goto fail;
		}
	} else {
		// IPv6
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char*)&scope, sizeof(scope)) != 0) {
			goto fail;
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off)) != 0) {
			goto fail;
		}
	}

	return sock;

fail:
	close(sock);

	log_warning("LPD: Cannot create send %s socket: %s",  str_af(af), strerror(errno));

	return -1;
}

static int create_receive_socket(const IP *mcast_addr)
{
	const int opt_off = 0;
	const int opt_on = 1;

	socklen_t addrlen = addr_len(mcast_addr);
	int af = mcast_addr->ss_family;

	int sock = net_socket("LPD", NULL, IPPROTO_UDP, af);
	if (sock < 0) {
		return -1;
	}

	if (af == AF_INET6) {
		// IPv6
		int loop = 0;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *)&loop, sizeof(loop)) < 0) {
			goto fail;
		}
	} else {
		// IPv4
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void const*)&opt_off, sizeof(opt_off)) != 0) {
			goto fail;
		}
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void const*)&opt_on, sizeof(opt_on)) != 0) {
		goto fail;
	}

	if (bind(sock, (struct sockaddr*)mcast_addr, addrlen) != 0) {
		goto fail;
	}

	return sock;

fail:

	close(sock);

	log_warning("LPD: Cannot create receive %s socket: %s", str_af(af), strerror(errno));

	return -1;
}

bool lpd_setup(void)
{
	bool ready = false;

	if (gconf->lpd_disable) {
		return true;
	}

	const char *ifname = gconf->dht_ifname;

	if (ifname && (gconf->af == AF_UNSPEC || gconf->af == AF_INET)) {
		log_warning("LPD: ifname setting not supported for IPv4");
	}

	addr_parse(&g_lpd4.mcast_addr, LPD_ADDR4, STR(LPD_PORT), AF_INET);
	addr_parse(&g_lpd6.mcast_addr, LPD_ADDR6, STR(LPD_PORT), AF_INET6);

	// Setup IPv4 sockets
	g_lpd4.sock_listen = create_receive_socket(&g_lpd4.mcast_addr);
	g_lpd4.sock_send = create_send_socket(AF_INET);

	// Setup IPv6 sockets
	g_lpd6.sock_listen = create_receive_socket(&g_lpd6.mcast_addr);
	g_lpd6.sock_send = create_send_socket(AF_INET6);

	if (g_lpd4.sock_listen >= 0 && g_lpd4.sock_send >= 0) {
		net_add_handler(g_lpd4.sock_listen, &handle_mcast4);
		ready = true;
	}

	if (g_lpd6.sock_listen >= 0 && g_lpd6.sock_send >= 0) {
		net_add_handler(g_lpd6.sock_listen, &handle_mcast6);
		ready = true;
	}

	return ready;
}

void lpd_free(void)
{
	// Nothing to do
}
