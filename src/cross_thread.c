/*
 *  (c) Philippe, philippe_44@outlook.com
 *
 */

#include <stdarg.h>

#if OSX
#include <sys/time.h>
#endif

#include "platform.h"
#include "cross_thread.h"
#include "cross_util.h"

/*----------------------------------------------------------------------------*/
/* locals */
/*----------------------------------------------------------------------------*/
static pthread_mutex_t	wake_mutex;
static pthread_cond_t	wake_cond;

/*----------------------------------------------------------------------------*/
/* 																			  */
/* system-wide sleep & wakeup												  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
static int wakeable_close(void) {
	pthread_mutex_destroy(&wake_mutex);
	pthread_cond_destroy(&wake_cond);
	return 0;
}

/*----------------------------------------------------------------------------*/
static void wakeable_open(void) {
	if (!wake_mutex || !wake_cond) {
		pthread_mutex_init(&wake_mutex, 0);
		pthread_cond_init(&wake_cond, 0);
		atexit(wakeable_close);
	}
}

/*----------------------------------------------------------------------------*/
void crossthreads_sleep(uint32_t ms) {
	wakeable_open();
	pthread_mutex_lock(&wake_mutex);
	if (ms) pthread_cond_reltimedwait(&wake_cond, &wake_mutex, ms);
	else pthread_cond_wait(&wake_cond, &wake_mutex);
	pthread_mutex_unlock(&wake_mutex);
}

/*----------------------------------------------------------------------------*/
void crossthreads_wake(void) {
	wakeable_open();
	pthread_mutex_lock(&wake_mutex);
	pthread_cond_broadcast(&wake_cond);
	pthread_mutex_unlock(&wake_mutex);
}

/*----------------------------------------------------------------------------*/
/* 																			  */
/* pthread utils															  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
int pthread_cond_reltimedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, uint32_t msWait)
{
	struct timespec ts;
	uint32_t	nsec;
#if OSX || SUNOS
	struct timeval tv;
#endif

#if WIN
	struct _timeb SysTime;

	_ftime(&SysTime);
	ts.tv_sec = (long) SysTime.time;
	ts.tv_nsec = 1000000 * SysTime.millitm;
#elif LINUX || FREEBSD
	clock_gettime(CLOCK_REALTIME, &ts);
#elif OSX || SUNOS
	gettimeofday(&tv, NULL);
	ts.tv_sec = (long) tv.tv_sec;
	ts.tv_nsec = 1000L * tv.tv_usec;
#endif

	if (!msWait) return pthread_cond_wait(cond, mutex);

	nsec = ts.tv_nsec + (msWait % 1000) * 1000000;
	ts.tv_sec += msWait / 1000 + (nsec / 1000000000);
	ts.tv_nsec = nsec % 1000000000;

	return pthread_cond_timedwait(cond, mutex, &ts);
}

// mutex wait with timeout
#if LINUX || FREEBSD
int _mutex_timedlock(pthread_mutex_t *m, uint32_t ms_wait)
{
	int rc = -1;
	struct timespec ts;

	if (!clock_gettime(CLOCK_REALTIME, &ts)) {
		ts.tv_nsec += (ms_wait % 1000) * 1000000;
		ts.tv_sec += ms_wait / 1000 + (ts.tv_nsec / 1000000000);
		ts.tv_nsec = ts.tv_nsec % 1000000000;
		rc = pthread_mutex_timedlock(m, &ts);
	}
	return rc;
}
#endif

#if OSX
int _mutex_timedlock(pthread_mutex_t *m, uint32_t ms_wait)
{
	int rc;
	s32_t wait = (s32_t) ms_wait;

	/* Try to acquire the lock and, if we fail, sleep for 10ms. */
	while (((rc = pthread_mutex_trylock (m)) == EBUSY) && (wait > 0)) {
		wait -= 10;
		usleep(10000);
	}

	return rc;
}
#endif
