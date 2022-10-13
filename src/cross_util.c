/*
 * Misc utilities
 *
 * (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE file
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include "platform.h"
#include "cross_util.h"

#if LINUX || OSX || FREEBSD || SUNOS
#include <ctype.h>
#if OSX
#include <sys/time.h>
#endif
#endif

#ifdef HAS_PTHREAD
#define mutex_lock(m) pthread_mutex_lock(&m)
#define mutex_unlock(m) pthread_mutex_unlock(&m)
#elif defined(_WIN32)
#define mutex_lock(m) WaitForSingleObject(m, INFINITE)
#define mutex_unlock(m) ReleaseMutex(m)
#else
#define mutex_lock(m) 
#define mutex_unlock(m)
#endif

#include "platform.h"
#include "cross_util.h"
#include "cross_log.h"

/*----------------------------------------------------------------------------*/
/* globals */
/*----------------------------------------------------------------------------*/
extern log_level	util_loglevel;

/*----------------------------------------------------------------------------*/
/* locals */
/*----------------------------------------------------------------------------*/
static log_level 	*loglevel = &util_loglevel;

/*----------------------------------------------------------------------------*/
/* 																			  */
/* Queue management															  */
/* 																			  */
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
void queue_init(queue_t *queue, bool mutex, void (*cleanup)(void*)) {
	queue->cleanup = cleanup;
	queue->list.item = NULL;
	queue->mutex = NULL;
	if (mutex) {
#ifdef HAS_PTHREAD
		pthread_mutex_init(&queue->mutex, NULL);
#elif defined(_WIN32)
		queue->mutex = CreateMutex(NULL, FALSE, NULL);
#endif
	}
}

/*----------------------------------------------------------------------------*/
void queue_insert(queue_t *queue, void *item) {
	struct _queue_s *list;

	if (queue->mutex) mutex_lock(queue->mutex);
	list = &queue->list;

	while (list->item) list = list->next;
	list->item = item;
	list->next = malloc(sizeof(struct _queue_s));
	list->next->item = NULL;

	if (queue->mutex) mutex_unlock(queue->mutex);
}


/*----------------------------------------------------------------------------*/
void *queue_extract(queue_t *queue) {
	void *item;
	struct _queue_s *list;

	if (queue->mutex) mutex_lock(queue->mutex);
	list = &queue->list;
	item = list->item;

	if (item) {
		struct _queue_s *next = list->next;
		if (next->item) {
			list->item = next->item;
			list->next = next->next;
		} else list->item = NULL;
		NFREE(next);
	}

	if (queue->mutex) mutex_unlock(queue->mutex);

	return item;
}


/*----------------------------------------------------------------------------*/
void queue_flush(queue_t *queue) {
	struct _queue_s *list;

	if (queue->mutex) mutex_lock(queue->mutex);

	list = &queue->list;

	while (list->item) {
		struct _queue_s *next = list->next;
		if (queue->cleanup)	(*(queue->cleanup))(list->item);
		if (list != &queue->list) { NFREE(list); }
		list = next;
	}

	if (list != &queue->list) { NFREE(list); }
	queue->list.item = NULL;

	if (queue->mutex) {
		mutex_unlock(queue->mutex);
#ifdef HAS_PTHREAD
		pthread_mutex_destroy(&queue->mutex);
#else 
		CloseHandle(queue->mutex);
#endif
	}
}

/*----------------------------------------------------------------------------*/
void queue_free_item(queue_t* queue, void* item) {
	if (queue->cleanup)	(*(queue->cleanup))(item);
}

/*----------------------------------------------------------------------------*/
/* 																			  */
/* LIST management															  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
list_t* list_push(list_t *item, list_t **list) {
  if (*list) item->next = *list;
  else item->next = NULL;

  *list = item;

  return item;
}


/*---------------------------------------------------------------------------*/
list_t* list_add_tail(list_t *item, list_t **list) {
  if (*list) {
	struct list_s *p = *list;
	while (p->next) p = p->next;
	item->next = p->next;
	p->next = item;
  } else {
	item->next = NULL;
	*list = item;
  }

  return item;
}


/*---------------------------------------------------------------------------*/
list_t* list_add_ordered(list_t *item, list_t **list, int (*compare)(void *a, void *b)) {
  if (*list) {
	struct list_s *p = *list;
	while (p->next && compare(p->next, item) <= 0) p = p->next;
	item->next = p->next;
	p->next = item;
  } else {
	item->next = NULL;
	*list = item;
  }

  return item;
}


/*---------------------------------------------------------------------------*/
list_t* list_pop(list_t **list) {
  if (*list) {
	list_t *item = *list;
	*list = item->next;
	return item;
  } else return NULL;
}


/*---------------------------------------------------------------------------*/
list_t* list_remove(list_t *item, list_t **list) {
  if (item != *list) {
	struct list_s *p = *list;
	while (p && p->next != item) p = p->next;
	if (p) p->next = item->next;
	item->next = NULL;
  } else *list = (*list)->next;

  return item;
}


/*---------------------------------------------------------------------------*/
void list_clear(list_t **list, void (*free_func)(void *)) {
  if (!*list) return;
  while (*list) {
	struct list_s *next = (*list)->next;
	if (free_func) (*free_func)(*list);
	else free(*list);
	*list = next;
  }
  *list = NULL;
}


/*----------------------------------------------------------------------------*/
/* 																			  */
/* Time & Clock															 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
uint32_t gettime_ms(void) {
#if WIN
	return GetTickCount();
#else
#if LINUX || FREEBSD
	struct timespec ts;
	if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
		return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
	}
#endif
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
#endif
}


/*----------------------------------------------------------------------------*/
uint64_t gettime_ms64(void) {
#if WIN
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	return (((uint64_t) ft.dwHighDateTime) << 32 | ft.dwLowDateTime) / 10000;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t) (tv.tv_sec + 0x83AA7E80) * 1000 + tv.tv_usec / 1000;
#endif
}


/*----------------------------------------------------------------------------*/
/* 																			  */
/* String extensions													 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
char* strextract(char *s1, char *beg, char *end)
{
	char *p1, *p2, *res;

	p1 = strcasestr(s1, beg);
	if (!p1) return NULL;

	p1 += strlen(beg);
	p2 = strcasestr(p1, end);
	if (!p2) return strdup(p1);

	res = malloc(p2 - p1 + 1);
	memcpy(res, p1, p2 - p1);
	res[p2 - p1] = '\0';

	return res;
}

#if !WIN
 /*---------------------------------------------------------------------------*/
char* itoa(int value, char* str, int radix) {
	static char dig[] =
		"0123456789"
		"abcdefghijklmnopqrstuvwxyz";
	int n = 0, neg = 0;
	unsigned int v;
	char* p, *q;
	char c;

	if (radix == 10 && value < 0) {
		value = -value;
		neg = 1;
	}
	v = value;
	do {
		str[n++] = dig[v%radix];
		v /= radix;
	} while (v);
	if (neg)
		str[n++] = '-';
	str[n] = '\0';

	for (p = str, q = p + (n-1); p < q; ++p, --q)
		c = *p, *p = *q, *q = c;
	return str;
}
#endif

/*---------------------------------------------------------------------------*/
int strremovechar(char* str, char c)
{
	int i = 0, j = 0, len;
	int num = 0;
	len = strlen(str);
	while (i < len) {
		if (str[i] == c) {
			for (j = i; j < len; j++) str[j] = str[j + 1];
			len--;
			num++;
		}
		else {
			i++;
		}
	}
	return num;
}

/*---------------------------------------------------------------------------*/
int hex2bytes(char* hex, uint8_t** bytes) {
	size_t i, len = strlen(hex) / 2;

	if (!*bytes && (*bytes = malloc(len)) == NULL) return 0;

	for (i = 0; i < len; i++) {
		sscanf(hex + i * 2, "%2hhx", *bytes + i);
	}

	return len;
}

/*---------------------------------------------------------------------------*/
uint32_t hash32(char *str)
{
	uint32_t hash = 5381;
	int32_t c;

	if (!str) return 0;

	while ((c = *str++) != 0)
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

	return hash;
}

/*---------------------------------------------------------------------------*/
char* strltrim(char *s) {
	while(isspace(*s)) s++;
	return s;
}

/*---------------------------------------------------------------------------*/
char* strrtrim(char *s) {
	char* back = s + strlen(s);
	while(isspace(*--back));
	*(back+1) = '\0';
	return s;
}

/*---------------------------------------------------------------------------*/
char* strtrim(char *s) {
	return strrtrim(strltrim(s));
}

/*----------------------------------------------------------------------------*/
/* 																			  */
/* Key-Value															 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
char *kd_lookup(key_data_t *kd, char *key) {
	int i = 0;
	while (kd && kd[i].key){
		if (!strcasecmp(kd[i].key, key)) return kd[i].data;
		i++;
	}
	return NULL;
}


/*----------------------------------------------------------------------------*/
bool kd_add(key_data_t *kd, char *key, char *data) {
	int i = 0;
	while (kd && kd[i].key) i++;

	kd[i].key = strdup(key);
	kd[i].data = strdup(data);
	kd[i+1].key = NULL;

	return true;
}

/*----------------------------------------------------------------------------*/
bool kd_vadd(key_data_t *kd, char *key, char *fmt, ...) {
	int i = 0;
	va_list args;
	while (kd && kd[i].key) i++;

	va_start(args, fmt);

	if (vasprintf(&kd[i].data, fmt, args)) {
		kd[i].key = strdup(key);
		kd[i+1].key = NULL;
		va_end(args);
		return true;
	}

	va_end(args);
	return false;
}


/*----------------------------------------------------------------------------*/
void kd_free(key_data_t *kd) {
	int i = 0;
	while (kd && kd[i].key){
		free(kd[i].key);
		if (kd[i].data) free(kd[i].data);
		i++;
	}

	kd[0].key = NULL;
}


/*----------------------------------------------------------------------------*/
char *kd_dump(key_data_t *kd) {
	int i = 0;
	int pos = 0, size = 0;
	char *str = NULL;

	if (!kd || !kd[0].key) return strdup("\r\n");

	while (kd && kd[i].key) {
		char *buf;
		int len;

		len = asprintf(&buf, "%s: %s\r\n", kd[i].key, kd[i].data);

		while (pos + len >= size) {
			void *p = realloc(str, size + 1024);
			size += 1024;
			if (!p) {
				free(str);
				return NULL;
			}
			str = p;
		}

		memcpy(str + pos, buf, len);

		pos += len;
		free(buf);
		i++;
	}

	str[pos] = '\0';

	return str;
}
