/*
 *  Thread-oriented utilities
 *
 *  (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE
 *
 */

#pragma once

#include <stdint.h>
#include "pthread.h"

void		crossthreads_sleep(uint32_t ms);
void		crossthreads_wake(void);

int			pthread_cond_reltimedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, uint32_t msWait);


