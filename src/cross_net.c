/*
 * Network-type utilities
 *
 * (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "platform.h"

#if LINUX || OSX || FREEBSD || SUNOS
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <ctype.h>
#if SUNOS
#include <sys/sockio.h>
#endif
#if FREEBSD
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#endif

#if WIN
#include <iphlpapi.h>
#elif OSX
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#endif

#include "cross_net.h"
#include "cross_log.h"

/*----------------------------------------------------------------------------*/
/* globals */
/*----------------------------------------------------------------------------*/
extern log_level	util_loglevel;

/*----------------------------------------------------------------------------*/
/* locals */
/*----------------------------------------------------------------------------*/
static log_level 		*loglevel = &util_loglevel;

/*----------------------------------------------------------------------------*/
/* 																			  */
/* NETWORK management													 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
// mac address
#if LINUX
// search first 4 interfaces returned by IFCONF
void get_mac(uint8_t mac[]) {
	struct ifconf ifc;
	struct ifreq *ifr, *ifend;
	struct ifreq ifreq;
	struct ifreq ifs[4];

	mac[0] = mac[1] = mac[2] = mac[3] = mac[4] = mac[5] = 0;

	int s = socket(AF_INET, SOCK_DGRAM, 0);

	ifc.ifc_len = sizeof(ifs);
	ifc.ifc_req = ifs;

	if (ioctl(s, SIOCGIFCONF, &ifc) == 0) {
		ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));

		for (ifr = ifc.ifc_req; ifr < ifend; ifr++) {
			if (ifr->ifr_addr.sa_family == AF_INET) {

				strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
				if (ioctl (s, SIOCGIFHWADDR, &ifreq) == 0) {
					memcpy(mac, ifreq.ifr_hwaddr.sa_data, 6);
					if (mac[0]+mac[1]+mac[2] != 0) {
						break;
					}
				}
			}
		}
	}

	close(s);
}
#elif OSX || FREEBSD
void get_mac(uint8_t mac[]) {
	struct ifaddrs *addrs, *ptr;
	const struct sockaddr_dl *dlAddr;
	const unsigned char *base;

	mac[0] = mac[1] = mac[2] = mac[3] = mac[4] = mac[5] = 0;

	if (getifaddrs(&addrs) == 0) {
		ptr = addrs;
		while (ptr) {
			if (ptr->ifa_addr->sa_family == AF_LINK && ((const struct sockaddr_dl *) ptr->ifa_addr)->sdl_type == IFT_ETHER) {
				dlAddr = (const struct sockaddr_dl *)ptr->ifa_addr;
				base = (const unsigned char*) &dlAddr->sdl_data[dlAddr->sdl_nlen];
				memcpy(mac, base, min(dlAddr->sdl_alen, 6));
				break;
			}
			ptr = ptr->ifa_next;
		}
		freeifaddrs(addrs);
	}
}
#elif WIN
#pragma comment(lib, "IPHLPAPI.lib")
void get_mac(uint8_t mac[]) {
	IP_ADAPTER_INFO AdapterInfo[16];
	DWORD dwBufLen = sizeof(AdapterInfo);
	DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);

	mac[0] = mac[1] = mac[2] = mac[3] = mac[4] = mac[5] = 0;

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_SUCCESS) {
		memcpy(mac, AdapterInfo[0].Address, 6);
	}
}
#endif



/*----------------------------------------------------------------------------*/
#if LINUX
int SendARP(in_addr_t src, in_addr_t dst, uint8_t mac[], uint32_t * size) {
	int                 s;
	struct arpreq       areq;
	struct sockaddr_in *sin;

	/* Get an internet domain socket. */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return -1;
	}

	/* Make the ARP request. */
	memset(&areq, 0, sizeof(areq));
	sin = (struct sockaddr_in *) &areq.arp_pa;
	sin->sin_family = AF_INET;

	sin->sin_addr.s_addr = src;
	sin = (struct sockaddr_in *) &areq.arp_ha;
	sin->sin_family = ARPHRD_ETHER;

	strncpy(areq.arp_dev, "eth0", 15);

	if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
		return -1;
	}

	memcpy(mac, &(areq.arp_ha.sa_data), *size);
	return 0;
}
#elif OSX
int SendARP(in_addr_t src, in_addr_t dst, uint8_t mac[], uint32_t* size) {
{
	int mib[6];
	size_t needed;
	char *lim, *buf, *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	int found_entry = -1;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
		return (found_entry);

	if ((buf = malloc(needed)) == NULL)
		return (found_entry);

	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
		return (found_entry);

	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen)
	{
		rtm = (struct rt_msghdr *)next;
		sin = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)(sin + 1);

		if (src)
		{
			if (src != sin->sin_addr.s_addr)
				continue;
		}

		if (sdl->sdl_alen)
		{
			found_entry = 0;
			memcpy(mac,  LLADDR(sdl), sdl->sdl_alen);
		}
	}

	free(buf);
	return (found_entry);
}
#elif !WIN
int SendARP(in_addr_t src, in_addr_t dst, uint8_t mac[], uint32_t * size) {
	LOG_WARN("No SendARP build for this platform", NULL);
	return 1;
}
#endif

#if LINUX || OSX || BSD || SUNOS
bool get_interface(struct in_addr *addr) {
	struct ifreq *ifreq;
	struct ifconf ifconf;
	char buf[512];
	unsigned i, nb;
	int fd;
	bool valid = false;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifconf.ifc_len = sizeof(buf);
	ifconf.ifc_buf = buf;

	if (ioctl(fd, SIOCGIFCONF, &ifconf)!=0) return false;

	ifreq = ifconf.ifc_req;
	nb = ifconf.ifc_len / sizeof(struct ifreq);

	for (i = 0; i < nb; i++) {
		ioctl(fd, SIOCGIFFLAGS, &ifreq[i]);
		//!(ifreq[i].ifr_flags & IFF_POINTTOPOINT);
		if ((ifreq[i].ifr_flags & IFF_UP) &&
			!(ifreq[i].ifr_flags & IFF_LOOPBACK) &&
			ifreq[i].ifr_flags & IFF_MULTICAST) {
				*addr = ((struct sockaddr_in *) &(ifreq[i].ifr_addr))->sin_addr;
				valid = true;
				break;
		 }
	}

	close(fd);
	return valid;
}
#elif WIN
bool get_interface(struct in_addr* addr) {
	struct sockaddr_in* host = NULL;
	ULONG size = sizeof(IP_ADAPTER_ADDRESSES) * 32;
	IP_ADAPTER_ADDRESSES* adapters = (IP_ADAPTER_ADDRESSES*)malloc(size);
	int ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapters, &size);

	for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter && !host; adapter = adapter->Next) {
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO) continue;
		if (adapter->OperStatus != IfOperStatusUp) continue;

		for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
			unicast = unicast->Next) {
			if (adapter->FirstGatewayAddress && unicast->Address.lpSockaddr->sa_family == AF_INET) {
				*addr = ((struct sockaddr_in*)unicast->Address.lpSockaddr)->sin_addr;
				return true;
			}
		}
	}

	addr->S_un.S_addr = INADDR_ANY;
	return false;
}
#endif

/*---------------------------------------------------------------------------*/
#define MAX_INTERFACES 256
#define DEFAULT_INTERFACE 1
#if !defined(_WIN32)
#define INVALID_SOCKET (-1)
#endif
in_addr_t get_localhost(char **name) {
#ifdef _WIN32
	char buf[256];
	struct hostent *h = NULL;
	struct sockaddr_in LocalAddr;

	memset(&LocalAddr, 0, sizeof(LocalAddr));

	gethostname(buf, 256);
	h = gethostbyname(buf);

	if (name) *name = strdup(buf);

	if (h != NULL) {
		memcpy(&LocalAddr.sin_addr, h->h_addr_list[0], 4);
		return LocalAddr.sin_addr.s_addr;
	}
	else return INADDR_ANY;
#elif defined (__APPLE__) || defined(__FreeBSD__)
	struct ifaddrs *ifap, *ifa;

	if (name) {
		*name = malloc(256);
		gethostname(*name, 256);
	}

	if (getifaddrs(&ifap) != 0) return INADDR_ANY;

	/* cycle through available interfaces */
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		/* Skip loopback, point-to-point and down interfaces,
		 * except don't skip down interfaces
		 * if we're trying to get a list of configurable interfaces. */
		if ((ifa->ifa_flags & IFF_LOOPBACK) ||
			(!( ifa->ifa_flags & IFF_UP))) {
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET) {
			/* We don't want the loopback interface. */
			if (((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr ==
				htonl(INADDR_LOOPBACK)) {
				continue;
			}
			return ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr;
			break;
		}
	}
	freeifaddrs(ifap);

	return INADDR_ANY;
#elif defined(linux) || defined(sun)
	char szBuffer[MAX_INTERFACES * sizeof (struct ifreq)];
	struct ifconf ifConf;
	struct ifreq ifReq;
	int nResult;
	long unsigned int i;
	int LocalSock;
	struct sockaddr_in LocalAddr;
	int j = 0;

	if (name) {
		*name = malloc(256);
		gethostname(*name, 256);
	}

	/* purify */
	memset(&ifConf,  0, sizeof(ifConf));
	memset(&ifReq,   0, sizeof(ifReq));
	memset(szBuffer, 0, sizeof(szBuffer));
	memset(&LocalAddr, 0, sizeof(LocalAddr));

	/* Create an unbound datagram socket to do the SIOCGIFADDR ioctl on.  */
	LocalSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (LocalSock == INVALID_SOCKET) return false;
	/* Get the interface configuration information... */
	ifConf.ifc_len = (int)sizeof szBuffer;
	ifConf.ifc_ifcu.ifcu_buf = (caddr_t) szBuffer;
	nResult = ioctl(LocalSock, SIOCGIFCONF, &ifConf);
	if (nResult < 0) {
		close(LocalSock);
		return INADDR_ANY;
	}

	/* Cycle through the list of interfaces looking for IP addresses. */
	for (i = 0lu; i < (long unsigned int)ifConf.ifc_len && j < DEFAULT_INTERFACE; ) {
		struct ifreq *pifReq =
			(struct ifreq *)((caddr_t)ifConf.ifc_req + i);
		i += sizeof *pifReq;
		/* See if this is the sort of interface we want to deal with. */
		memset(ifReq.ifr_name, 0, sizeof(ifReq.ifr_name));
		memcpy(ifReq.ifr_name, pifReq->ifr_name,
			sizeof(ifReq.ifr_name) - 1);
		/* Skip loopback, point-to-point and down interfaces,
		 * except don't skip down interfaces
		 * if we're trying to get a list of configurable interfaces. */
		ioctl(LocalSock, SIOCGIFFLAGS, &ifReq);
		if ((ifReq.ifr_flags & IFF_LOOPBACK) ||
			(!(ifReq.ifr_flags & IFF_UP))) {
			continue;
		}
		if (pifReq->ifr_addr.sa_family == AF_INET) {
			/* Get a pointer to the address...*/
			memcpy(&LocalAddr, &pifReq->ifr_addr,
				sizeof pifReq->ifr_addr);
			/* We don't want the loopback interface. */
			if (LocalAddr.sin_addr.s_addr ==
				htonl(INADDR_LOOPBACK)) {
				continue;
			}
		}
		/* increment j if we found an address which is not loopback
		 * and is up */
		j++;
	}
	close(LocalSock);

	return LocalAddr.sin_addr.s_addr;
#else
	// missing platform here ...
	return INADDR_ANY;
#endif
}

/*----------------------------------------------------------------------------*/
void netsock_init(void) {
#if WIN
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int WSerr = WSAStartup(wVersionRequested, &wsaData);
	if (WSerr != 0) {
		LOG_ERROR("Bad winsock version", NULL);
		exit(1);
	}
#endif
}

/*----------------------------------------------------------------------------*/
void netsock_close(void) {
#if WIN
	WSACleanup();
#endif
}

/*----------------------------------------------------------------------------*/
int shutdown_socket(int sd) {
	if (sd <= 0) return -1;

#if WIN
	shutdown(sd, SD_BOTH);
#else
	shutdown(sd, SHUT_RDWR);
#endif
	return closesocket(sd);
}

/*----------------------------------------------------------------------------*/
void set_nonblock(int sd) {
#if WIN
	u_long iMode = 1;
	ioctlsocket(sd, FIONBIO, &iMode);
#else
	int flags = fcntl(sd, F_GETFL, 0);
	fcntl(sd, F_SETFL, flags | O_NONBLOCK);
#endif
}

/*----------------------------------------------------------------------------*/
void set_block(int sd) {
#if WIN
	u_long iMode = 0;
	ioctlsocket(sd, FIONBIO, &iMode);
#else
	int flags = fcntl(sd, F_GETFL, 0);
	fcntl(sd, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

/*----------------------------------------------------------------------------*/
void set_nosigpipe(int sd) {
#if OSX
	int set = 1;
	setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, (void*)&set, sizeof(int));
#endif
}

/*----------------------------------------------------------------------------*/
bool tcp_connect(int sd, struct sockaddr_in peer) {
	for (size_t count = 0; count < 2; count++) {
		if (connect(sd, (struct sockaddr*) &peer, sizeof(struct sockaddr)) < 0) {
			return true;
		}
		usleep(100 * 1000);
	}

	LOG_ERROR("cannot connect addr=%s, port=%d", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
	return false;
}

/*----------------------------------------------------------------------------*/
bool tcp_connect_by_host(int sd, struct in_addr peer, unsigned short port) {
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = peer.s_addr;
	addr.sin_port = htons(port);

	return tcp_connect(sd, addr);
}

/*----------------------------------------------------------------------------*/
int tcp_connect_loopback(unsigned short port) {
	struct sockaddr_in addr;
	int sd;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);

	if (sd < 0 || connect(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(sd);
		return -1;
	}

	LOG_DEBUG("created socket %d", sd);

	return sd;
}

/*----------------------------------------------------------------------------*/
// connect for socket already set to non blocking with timeout in ms
int tcp_connect_timeout(int sd, const struct sockaddr_in addr, int seconds) {
	fd_set w, e;
	struct timeval tval;
	socklen_t addrlen = sizeof(addr);

	if (connect(sd, (struct sockaddr*) &addr, addrlen) < 0) {
#if WIN
		if (last_error() != WSAEWOULDBLOCK) {
#else
		if (last_error() != EINPROGRESS) {
#endif
			return -1;
		}
	}

	FD_ZERO(&w);
	FD_SET(sd, &w);
	e = w;
	tval.tv_sec = seconds / 1000;
	tval.tv_usec = (seconds - tval.tv_sec * 1000) * 1000;

	// only return 0 if w set and sock error is zero, otherwise return error code
	if (select(sd + 1, NULL, &w, &e, seconds ? &tval : NULL) == 1 && FD_ISSET(sd, &w)) {
		int	error = 0;
		socklen_t len = sizeof(error);
		getsockopt(sd, SOL_SOCKET, SO_ERROR, (void*)&error, &len);
		return error;
	}

	return -1;
}

/*----------------------------------------------------------------------------*/
int open_tcp_socket(struct in_addr host, unsigned short* port, bool blocking) {
	int sd;
	int optval = 1;

	/* socket creation */
	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (blocking) set_block(sd);
	else set_nonblock(sd);

	if (sd < 0) {
		LOG_ERROR("cannot create tcp socket %x", host);
		return -1;
	}

	setsockopt(sd, SOL_SOCKET, SO_KEEPALIVE, (void*)&optval, sizeof(optval));
#if 0 //only Linux supports this
	optval = 120;
	optval = setsockopt(sd, SOL_TCP, TCP_KEEPIDLE, &optval, sizeof(optval));
	optval = 60;
	optval = setsockopt(sd, SOL_TCP, TCP_KEEPINTVL, &optval, sizeof(optval));
	optval = 10;
	optval = setsockopt(sd, SOL_TCP, TCP_KEEPCNT, &optval, sizeof(optval));
#endif

	if (!bind_host(sd, host, port)) {
		closesocket(sd);
		return -1;
	}

	return sd;
}

/*----------------------------------------------------------------------------*/
int open_udp_socket(struct in_addr host, unsigned short* port, bool blocking) {
	int sd;

	/*socket creation*/
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (!blocking) set_nonblock(sd);

	if (sd < 0) {
		LOG_ERROR("cannot create udp socket %x", host);
		return -1;
	}

	if (!bind_host(sd, host, port)) {
		closesocket(sd);
		return -1;
	}
	return sd;
}

/*----------------------------------------------------------------------------*/
int bind_socket(struct in_addr host, unsigned short* port, int mode) {
	int sock;

	if ((sock = socket(AF_INET, mode, 0)) < 0) {
		LOG_ERROR("cannot create socket %d", sock);
		return sock;
	}

	if (!bind_host(sock, host, port)) {
		closesocket(sock);
		return -1;
	}

	LOG_INFO("socket binding %d on port %d", sock, *port);

	return sock;
}

/*----------------------------------------------------------------------------*/
bool bind_host(int sd, struct in_addr host, unsigned short* port) {
	struct sockaddr_in addr;
	socklen_t nlen = sizeof(struct sockaddr);

	memset(&addr, 0, sizeof(addr));

	addr.sin_addr.s_addr = host.s_addr;
	addr.sin_family = AF_INET;
	addr.sin_port = port ? htons(*port) : 0;
#ifdef SIN_LEN
	addr.sin_len = sizeof(si);
#endif

	if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		LOG_ERROR("cannot bind: %s", strerror(errno));
		return false;
	}

	if (port && *port == 0) {
		getsockname(sd, (struct sockaddr*)&addr, &nlen);
		*port = ntohs(addr.sin_port);
	}

	return true;
}


/*----------------------------------------------------------------------------*/
/* 																			  */
/* HTTP management														 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
bool http_parse(int sock, char* method, char* resource, char* proto, key_data_t* rkd, char** body, int* len) {
	char* request = NULL;
	bool res = http_parse_simple(sock, &request, rkd, body, len);

	if (res && request) {
		if (method) sscanf(request, "%s", method);
		if (resource) sscanf(request, "%*s%s", resource);
		if (proto) sscanf(request, "%*s%*s%s", proto);
	}

	return res;
}

/*----------------------------------------------------------------------------*/
bool http_parse_simple(int sock, char **request, key_data_t* rkd, char** body, int* len) {
	char line[1024];
	int i, timeout = 100;

	rkd[0].key = NULL;

	if ((i = http_read_line(sock, line, sizeof(line), timeout, true)) <= 0) {
		if (i < 0) {
			LOG_ERROR("cannot read method", NULL);
		}
		return false;
	}

	if (request) *request = strdup(line);

	i = *len = 0;
		
	while (http_read_line(sock, line, sizeof(line), timeout, true) > 0) {

		LOG_DEBUG("sock: %u, received %s", sock, line);

		// line folding should be deprecated
		if (i && rkd[i].key && (line[0] == ' ' || line[0] == '\t')) {
			unsigned j;
			for (j = 0; j < strlen(line); j++) if (line[j] != ' ' && line[j] != '\t') break;
			rkd[i].data = realloc(rkd[i].data, strlen(rkd[i].data) + strlen(line + j) + 1);
			strcat(rkd[i].data, line + j);
			continue;
		}

		char* dp = strstr(line, ":");

		if (!dp) {
			LOG_ERROR("Request failed, bad header", NULL);
			kd_free(rkd);
			return false;
		}

		*dp = 0;
		rkd[i].key = strdup(line);
		rkd[i].data = strdup(strltrim(dp + 1));

		if (!strcasecmp(rkd[i].key, "Content-Length")) *len = atol(rkd[i].data);

		i++;
		rkd[i].key = NULL;
	}

	if (*len) {
		int size = 0;

		*body = malloc(*len + 1);
		while (*body && size < *len) {
			int bytes = recv(sock, *body + size, *len - size, 0);
			if (bytes <= 0) break;
			size += bytes;
		}

		(*body)[*len] = '\0';

		if (!*body || size != *len) {
			LOG_ERROR("content length receive error %d %d", *len, size);
		}
	}

	return true;
}

/*----------------------------------------------------------------------------*/
int http_read_line(int fd, char* line, int maxlen, int timeout, bool polling) {
	int i, rval;
	int count = 0;
	struct pollfd pfds;
	char ch;

	*line = 0;
	pfds.fd = fd;
	pfds.events = POLLIN;

	for (i = 0; i < maxlen; i++) {
		if (!polling || poll(&pfds, 1, timeout)) rval = recv(fd, &ch, 1, 0);
		else return 0;

		if (rval == -1) {
			if (errno == EAGAIN) return 0;
			LOG_ERROR("fd: %d read error: %s", fd, strerror(errno));
			return -1;
		}

		if (rval == 0) {
			LOG_INFO("disconnected on the other end %u", fd);
			return 0;
		}

		if (ch == '\n') {
			*line = 0;
			return count;
		}

		if (ch == '\r') continue;

		*line++ = ch;
		count++;
		if (count >= maxlen - 1) break;
	}

	*line = 0;
	return count;
}


/*----------------------------------------------------------------------------*/
char* http_send(int sock, char* method, key_data_t* rkd) {
	unsigned sent, len;
	char* resp = kd_dump(rkd);
	char* data = malloc(strlen(method) + 2 + strlen(resp) + 2 + 1);

	len = sprintf(data, "%s\r\n%s\r\n", method, resp);
	NFREE(resp);

	sent = send(sock, data, len, 0);

	if (sent != len) {
		LOG_ERROR("HTTP send() error:%s %u (strlen=%u)", data, sent, len);
		NFREE(data);
	}

	return data;
}

