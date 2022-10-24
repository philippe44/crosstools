/*
 * Network-oriented utilities
 *
 * (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE file
 *
 */

#pragma once

#include "platform.h"
#include "cross_util.h"

#if WIN
#define last_error() WSAGetLastError()
#define ERROR_WOULDBLOCK WSAEWOULDBLOCK
#else
#define last_error() errno
#define ERROR_WOULDBLOCK EWOULDBLOCK
#endif

struct in_addr	get_interface(char *iface);
in_addr_t 	get_localhost(char **name);
void 		get_mac(uint8_t mac[]);
void 		netsock_init(void);
void 		netsock_close(void);

void		set_nonblock(int sd);
void		set_block(int sd);
void		set_nosigpipe(int sd);
int 		shutdown_socket(int sd);
int 		bind_socket(struct in_addr host, short unsigned *port, int mode);
bool		bind_host(int sd, struct in_addr host, unsigned short* port);
int 		tcp_connect_loopback(unsigned short port);
bool		tcp_connect(int sd, struct sockaddr_in peer);
bool		tcp_connect_by_host(int sd, struct in_addr peer, unsigned short port);
int         tcp_connect_timeout(int sd, const struct sockaddr_in addr, int seconds);
int			open_tcp_socket(struct in_addr host, unsigned short* port, bool blocking);
int			open_udp_socket(struct in_addr host, unsigned short* port, bool blocking);

bool 		http_parse_simple(int sd, char** request, key_data_t* rkd, char** body, int* len);
bool 		http_parse(int sd, char *method, char *resource, char *proto, key_data_t *rkd, char **body, int *len);
char*		http_send(int sd, char *method, key_data_t *rkd);
int			http_read_line(int fd, char* line, int maxlen, int timeout, bool polling);
int 		http_send_response(int sd, char *response);
