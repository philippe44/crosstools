/*
 * Logging utilities
 *
 *  (c) Adrian Smith 2012-2015, triode1@btinternet.com
 *  Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#include <sys/time.h>
#endif

#include "cross_log.h"

// logging functions
const char *logtime(void) {
	static char buf[100];
#ifdef _WIN32
	SYSTEMTIME lt;
	GetLocalTime(&lt);
	sprintf(buf, "[%02d:%02d:%02d.%03d]", lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	strftime(buf, sizeof(buf), "[%T.", localtime(&tv.tv_sec));
	sprintf(buf+strlen(buf), "%06ld]", (long)tv.tv_usec);
#endif
	return buf;
}

/*---------------------------------------------------------------------------*/
void logprint(const char *fmt, ...) {
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fflush(stderr);
}

/*---------------------------------------------------------------------------*/
void logdump(const char* data, size_t size) {
	size_t count = 0;
	while (size) {
		size_t col = size > 16 ? 16 : size;
		fprintf(stderr, "%04x  ", (unsigned int) count);
		for (size_t i = 0; i < col; i++) fprintf(stderr, "%02x ", (unsigned char) data[i]);
		for (size_t i = 0; i < col; i++) isprint((unsigned char) data[i]) ? putc(data[i], stderr) : putc(' ', stderr);
		putc('\n', stderr);
		data += col; size -= col; count += col;
	}
}

/*---------------------------------------------------------------------------*/
log_level debug2level(char *level)
{
	if (!strcmp(level, "error")) return lERROR;
	if (!strcmp(level, "warn")) return lWARN;
	if (!strcmp(level, "info")) return lINFO;
	if (!strcmp(level, "debug")) return lDEBUG;
	if (!strcmp(level, "sdebug")) return lSDEBUG;
	return lWARN;
}

/*---------------------------------------------------------------------------*/
char *level2debug(log_level level)
{
	switch (level) {
	case lERROR: return "error";
	case lWARN: return "warn";
	case lINFO: return "info";
	case lDEBUG: return "debug";
	case lSDEBUG: return "debug";
	default: return "warn";
	}
}
