/*
 *  Platform setting definition
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 *
 */

#pragma once

#if defined(linux)
#define LINUX     1
#define OSX       0
#define WIN       0
#define FREEBSD   0
#elif defined (__APPLE__)
#define LINUX     0
#define OSX       1
#define WIN       0
#define FREEBSD   0
#elif defined (_MSC_VER) || defined(__BORLANDC__)
#define LINUX     0
#define OSX       0
#define WIN       1
#define FREEBSD   0
#elif defined(__FreeBSD__)
#define LINUX     0
#define OSX       0
#define WIN       0
#define FREEBSD   1
#elif defined(sun)
#define LINUX     0
#define OSX       0
#define WIN       0
#define FREEBSD   0
#define SUNOS	  1
#else
#error unknown target
#endif

#include <stdbool.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdint.h>
#include <inttypes.h>

#if LINUX || OSX || FREEBSD || SUNOS
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/poll.h>
#include <poll.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

#define last_error() errno
#define ERROR_WOULDBLOCK EWOULDBLOCK

int SendARP(in_addr_t src, in_addr_t dst, uint8_t mac[], uint32_t *size);
#define fresize(f,s) ftruncate(fileno(f), s)
char *strlwr(char *str);
char* itoa(int value, char* str, int radix);
#define closesocket(s) close(s)

#endif

#if WIN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <iphlpapi.h>
#include <sys/timeb.h>

#define usleep(x) Sleep((x)/1000)
#define sleep(x) Sleep((x)*1000)

#define open _open
#define read _read

#define fresize(f, s) chsize(fileno(f), s)

int on_exit(void (*function)(int, void*), void* arg);

int poll(struct pollfd* fds, unsigned long numfds, int timeout);

int asprintf(char** s, const char* fmt, ...);
int vasprintf(char** strp, const char* fmt, va_list args);

#define strcasecmp stricmp
char* strcasestr(const char* haystack, const char* needle);
char* strsep(char** stringp, const char* delim);
char* strndup(const char* s, size_t n);

#define VALGRIND_MAKE_MEM_DEFINED(x,y)

#define __attribute__(X)
typedef uint32_t in_addr_t;
#define socklen_t int
typedef SSIZE_T	ssize_t;

#define RTLD_NOW 0

#endif

#define CROSS_VERSION 1
bool cross_checkversion(int version);
