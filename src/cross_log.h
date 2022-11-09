/*
 *  Logging utility
 *
 *  (c) Adrian Smith 2012-2015, triode1@btinternet.com
 *  Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 * 
 */

#pragma once

typedef enum { lSILENCE = 0, lERROR, lWARN, lINFO, lDEBUG, lSDEBUG } log_level;

const char *logtime(void);
void logprint(const char *fmt, ...);
log_level debug2level(char *level);
char *level2debug(log_level level);
void logdump(const char* data, size_t size);

#define LOG_ERROR(fmt, ...)  if (*loglevel >= lERROR)  logprint("%s %s:%d " fmt "\n", logtime(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)   if (*loglevel >= lWARN)  logprint("%s %s:%d " fmt "\n", logtime(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)   if (*loglevel >= lINFO)  logprint("%s %s:%d " fmt "\n", logtime(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...)  if (*loglevel >= lDEBUG) logprint("%s %s:%d " fmt "\n", logtime(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_SDEBUG(fmt, ...) if (*loglevel >= lSDEBUG) logprint("%s %s:%d " fmt "\n", logtime(), __FUNCTION__, __LINE__, ##__VA_ARGS__)
