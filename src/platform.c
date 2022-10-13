/*
 * Cross-platforms functions
 * 
 * (c) Philippe, philippe_44@outlook.com: 
 *
 * See LICENSE
 * 
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>

#include "platform.h"

#ifdef WIN
#include <VersionHelpers.h>
#endif

/*----------------------------------------------------------------------------*/
bool crosscheck_version(int version) {
	assert(version == CROSS_VERSION);
	return true;
}

/*----------------------------------------------------------------------------*/
/* 																			  */
/* Network																 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
#if WIN
int poll(struct pollfd *fds, unsigned long numfds, int timeout) {
	// WSAPoll is broken till Windows 10, see NOTe on https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll
	if (numfds > 1 || IsWindows10OrGreater()) {
		return WSAPoll(fds, numfds, timeout);
	} else {
		fd_set r, w;
		struct timeval tv;

		FD_ZERO(&r);
		FD_ZERO(&w);

		if (fds[0].events & POLLIN) FD_SET(fds[0].fd, &r);
		if (fds[0].events & POLLOUT) FD_SET(fds[0].fd, &w);

		tv.tv_sec = timeout / 1000;
		tv.tv_usec = 1000 * (timeout % 1000);

		int ret = select(fds[0].fd + 1, &r, &w, NULL, &tv);

		if (ret < 0) return ret;

		fds[0].revents = 0;
		if (FD_ISSET(fds[0].fd, &r)) fds[0].revents |= POLLIN;
		if (FD_ISSET(fds[0].fd, &w)) fds[0].revents |= POLLOUT;

		return ret;
	}
}
#endif

/*----------------------------------------------------------------------------*/
/* 																			  */
/* stdlib/string														 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

#if WIN
/*----------------------------------------------------------------------------*/
int asprintf(char** strp, const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	int len = vasprintf(strp, fmt, args);
	va_end(args);

	return len;
}

/*----------------------------------------------------------------------------*/
int vasprintf(char** strp, const char* fmt, va_list args)
{
	int len = vsnprintf(NULL, 0, fmt, args);
	*strp = malloc(len + 1);

	if (*strp) len = vsprintf(*strp, fmt, args);
	else len = 0;

	return len;
}
#endif

#if LINUX || OSX || FREEBSD || SUNOS
/*---------------------------------------------------------------------------*/
char* strlwr(char* str)
{
	char* p = str;
	while (*p) {
		*p = tolower(*p);
		p++;
	}
	return str;
}
#endif

#if WIN
/*---------------------------------------------------------------------------*/
char* strcasestr(const char* haystack, const char* needle)
{
	char* haystack_lwr, * needle_lwr, * p;

	haystack_lwr = strlwr(strdup(haystack));
	needle_lwr = strlwr(strdup(needle));
	p = strstr(haystack_lwr, needle_lwr);

	if (p) p = (char*)haystack + (p - haystack_lwr);
	free(haystack_lwr);
	free(needle_lwr);
	return p;
}

/*---------------------------------------------------------------------------*/
char* strsep(char** stringp, const char* delim)
{
	char* start = *stringp;
	char* p;

	p = (start != NULL) ? strpbrk(start, delim) : NULL;

	if (p == NULL) {
		*stringp = NULL;
	}
	else {
		*p = '\0';
		*stringp = p + 1;
	}

	return start;
}

/*---------------------------------------------------------------------------*/
char* strndup(const char* s, size_t n) {
	char* p = malloc(n + 1);
	strncpy(p, s, n);
	p[n] = '\0';

	return p;
}
#endif

#if !WIN
/*---------------------------------------------------------------------------*/
char* itoa(int value, char* str, int radix) {
	static char dig[] =
		"0123456789"
		"abcdefghijklmnopqrstuvwxyz";
	int n = 0, neg = 0;
	unsigned int v;
	char* p, * q;
	char c;

	if (radix == 10 && value < 0) {
		value = -value;
		neg = 1;
	}
	v = value;
	do {
		str[n++] = dig[v % radix];
		v /= radix;
	} while (v);
	if (neg)
		str[n++] = '-';
	str[n] = '\0';

	for (p = str, q = p + (n - 1); p < q; ++p, --q)
		c = *p, * p = *q, * q = c;
	return str;
}
#endif


/*----------------------------------------------------------------------------*/
/* 																			  */
/* SYSTEM utils															 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

#if WIN
/*----------------------------------------------------------------------------*/
void* dlopen(const char* filename, int flag) {
	SetLastError(0);
	return LoadLibrary((LPCTSTR)filename);
}

/*----------------------------------------------------------------------------*/
void* dlsym(void* handle, const char* symbol) {
	SetLastError(0);
	return (void*)GetProcAddress(handle, symbol);
}

/*----------------------------------------------------------------------------*/
char* dlerror(void) {
	static char ret[32];
	int last = GetLastError();
	if (last) {
		sprintf(ret, "code: %i", last);
		SetLastError(0);
		return ret;
	}
	return NULL;
}

/*----------------------------------------------------------------------------*/
int on_exit(void (*function)(int, void*), void* arg) {
	return 0;
}
#endif

/*----------------------------------------------------------------------------*/
#if LINUX || FREEBSD || OSX
char* GetTempPath(uint16_t size, char* path)
{
	strncpy(path, P_tmpdir, size);
	if (!strlen(path)) strncpy(path, "/var/tmp", size);
	path[size - 1] = '\0';
	return path;
}
#endif