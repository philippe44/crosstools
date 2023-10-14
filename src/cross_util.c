/*
 * Misc utilities
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
#include "cross_util.h"

#if LINUX || OSX || FREEBSD || SUNOS
#include <ctype.h>
#if OSX
#include <sys/time.h>
#endif
#endif

#ifdef HAS_PTHREAD
#define mutex_lock(m) pthread_mutex_lock(m)
#define mutex_unlock(m) pthread_mutex_unlock(m)
#elif defined(_WIN32)
#define mutex_lock(m) WaitForSingleObject(*m, INFINITE)
#define mutex_unlock(m) ReleaseMutex(*m)
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
static __attribute__((unused)) log_level *loglevel = &util_loglevel;

/*----------------------------------------------------------------------------*/
/* 																			  */
/* Queue management															  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
void queue_init(cross_queue_t *queue, bool mutex, void (*cleanup)(void*)) {
	queue->cleanup = cleanup;
	queue->head.item = NULL;
	queue->mutex = NULL;
	if (mutex) {
#ifdef HAS_PTHREAD
		queue->mutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(queue->mutex, NULL);
#elif defined(_WIN32)
		queue->mutex = (HANDLE*) malloc(sizeof(HANDLE));
		*queue->mutex = CreateMutex(NULL, FALSE, NULL);
#endif
	}
}

/*----------------------------------------------------------------------------*/
void queue_lock(cross_queue_t* queue) {
	if (queue->mutex) mutex_lock(queue->mutex);
}

/*----------------------------------------------------------------------------*/
void queue_unlock(cross_queue_t* queue) {
	if (queue->mutex) mutex_unlock(queue->mutex);
}

/*----------------------------------------------------------------------------*/
void queue_insert(cross_queue_t *queue, void *item) {
	struct _cross_queue_s *list;

	if (queue->mutex) mutex_lock(queue->mutex);
	list = &queue->head;

	while (list->item) list = list->next;
	list->item = item;
	list->next = malloc(sizeof(struct _cross_queue_s));
	list->next->item = NULL;

	if (queue->mutex) mutex_unlock(queue->mutex);
}

/*----------------------------------------------------------------------------*/
void queue_insert_first(cross_queue_t* queue, void* item) {
	struct _cross_queue_s* next;

	if (queue->mutex) mutex_lock(queue->mutex);

	next = malloc(sizeof(struct _cross_queue_s));
	memcpy(next, &queue->head, sizeof(struct _cross_queue_s));
	queue->head.item = item;
	queue->head.next = next;

	if (queue->mutex) mutex_unlock(queue->mutex);
}

/*----------------------------------------------------------------------------*/
void *queue_extract(cross_queue_t *queue) {
	if (queue->mutex) mutex_lock(queue->mutex);
	
	void *item = queue->head.item;

	// if there an item, there is a valid next
	if (item) {
		struct _cross_queue_s *next = queue->head.next;
		queue->head.item = next->item;
		queue->head.next = next->next;
		free(next);
	}

	if (queue->mutex) mutex_unlock(queue->mutex);

	return item;
}

/*----------------------------------------------------------------------------*/
bool queue_extract_item(cross_queue_t* queue, void* item) {
	bool success = false;
	if (queue->mutex) mutex_lock(queue->mutex);
	struct _cross_queue_s* previous = &queue->head;

	for (struct _cross_queue_s* walker = previous; walker->item; previous = walker, walker = walker->next) {
		if (walker->item != item) continue;

		// need to memorize what we'll free up
		void* p = walker == &queue->head ? walker->next : walker;
		
		// pop one item regardless
		memcpy(previous, walker->next, sizeof(struct _cross_queue_s));
		free(p);
		
		success = true;
		break;
	}

	if (queue->mutex) mutex_unlock(queue->mutex);
	return success;
}

size_t	queue_count(cross_queue_t* queue) {
	if (queue->mutex) mutex_lock(queue->mutex);

	size_t count = 0;
	for (struct _cross_queue_s* walker = &queue->head; walker->item; count++) {
		walker = walker->next;
	}
	
	if (queue->mutex) mutex_unlock(queue->mutex);
	return count;
}

/*----------------------------------------------------------------------------*/
void* queue_walk_start(cross_queue_t* queue) {
	if (queue->mutex) mutex_lock(queue->mutex);
	queue->walker = &queue->head;
	queue->walk = true;
	return queue->walker->item;
}

/*----------------------------------------------------------------------------*/
void queue_walk_end(cross_queue_t* queue) {
	if (queue->mutex) mutex_unlock(queue->mutex);
}

/*----------------------------------------------------------------------------*/
void* queue_walk_next(cross_queue_t* queue) {
	if (queue->walker->item && queue->walk) queue->walker = queue->walker->next;
	queue->walk = true;
	return queue->walker->item;
}

/*----------------------------------------------------------------------------*/
void* queue_walk_extract(cross_queue_t* queue) {
	void* item = queue->walker->item;
	void *release = queue->walker->next;

	memcpy(queue->walker, queue->walker->next, sizeof(struct _cross_queue_s));
	free(release);
	
	queue->walk = false;
	return item;
}

/*----------------------------------------------------------------------------*/
void queue_flush(cross_queue_t *queue) {
	struct _cross_queue_s *walker;

	if (queue->mutex) mutex_lock(queue->mutex);

	walker = &queue->head;

	while (walker->item) {
		struct _cross_queue_s *next = walker->next;
		if (queue->cleanup)	queue->cleanup(walker->item);
		if (walker != &queue->head) { NFREE(walker); }
		walker = next;
	}

	if (walker != &queue->head) free(walker);
	queue->head.item = NULL;

	if (queue->mutex) {
		mutex_unlock(queue->mutex);
#ifdef HAS_PTHREAD
		pthread_mutex_destroy(queue->mutex);
#else 
		CloseHandle(*queue->mutex);
#endif
		free(queue->mutex);
	}
}

/*----------------------------------------------------------------------------*/
void queue_free_item(cross_queue_t* queue, void* item) {
	if (queue->cleanup)	(*(queue->cleanup))(item);
}

/*----------------------------------------------------------------------------*/
/* 																			  */
/* LIST management															  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
cross_list_t* list_push(cross_list_t *item, cross_list_t **list) {
  if (*list) item->next = *list;
  else item->next = NULL;

  *list = item;

  return item;
}

/*---------------------------------------------------------------------------*/
cross_list_t* list_add_tail(cross_list_t *item, cross_list_t **list) {
  if (*list) {
	struct cross_list_s *p = *list;
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
cross_list_t* list_add_ordered(cross_list_t *item, cross_list_t **list, int (*compare)(void *a, void *b)) {
  if (*list) {
	struct cross_list_s *p = *list;
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
cross_list_t* list_pop(cross_list_t **list) {
  if (*list) {
	cross_list_t *item = *list;
	*list = item->next;
	return item;
  } else return NULL;
}

/*---------------------------------------------------------------------------*/
cross_list_t* list_remove(cross_list_t *item, cross_list_t **list) {
  if (item != *list) {
	struct cross_list_s *p = *list;
	while (p && p->next != item) p = p->next;
	if (p) p->next = item->next;
	item->next = NULL;
  } else *list = (*list)->next;

  return item;
}

/*---------------------------------------------------------------------------*/
void list_clear(cross_list_t **list, void (*free_func)(void *)) {
  if (!*list) return;
  while (*list) {
	struct cross_list_s *next = (*list)->next;
	if (free_func) (*free_func)(*list);
	else free(*list);
	*list = next;
  }
  *list = NULL;
}


/*----------------------------------------------------------------------------*/
/* 																			  */
/* Time, Clock & System													 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
uint32_t gettime_ms(void) {
	return gettime_us() / 1000;
}

/*----------------------------------------------------------------------------*/
uint64_t gettime_ms64(void) {
	return gettime_us() / 1000;
}

/*----------------------------------------------------------------------------*/
// this is EPOCH-based, so suitable for NTP
uint64_t gettime_us(void) {
#if WIN
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	//@FIXME => check time and epoch vs 01/01/1601
	return ((uint64_t) ft.dwHighDateTime << 32 | ft.dwLowDateTime) / 10 + 0x83AA7E80LL * 1000 * 1000;
#else
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t) tv.tv_sec * 1000*1000 + tv.tv_usec;
#endif
}

/*----------------------------------------------------------------------------*/
void touch_memory(uint8_t* buf, size_t size) {
#if LINUX || FREEBSD || SUNOS
	uint8_t* ptr;
	for (ptr = buf; ptr < buf + size; ptr += sysconf(_SC_PAGESIZE)) {
		*ptr = 0;
	}
#else
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
bool kd_add(key_data_t *kd, const char *key, const char *data) {
	int i = 0;
	while (kd && kd[i].key) i++;

	kd[i].key = strdup(key);
	kd[i].data = strdup(data);
	kd[i+1].key = NULL;

	return true;
}

/*----------------------------------------------------------------------------*/
bool kd_vadd(key_data_t *kd, const char *key, const char *fmt, ...) {
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

	if (!kd || !kd[0].key) return strdup("");

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

/*----------------------------------------------------------------------------*/
/* 																			  */
/* URL handling															 	  */
/* 																			  */
/*----------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*/
/* Converts a hex character to its integer value */
static char from_hex(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/*---------------------------------------------------------------------------*/
/* Converts an integer value to its hex character*/
static char to_hex(char code) {
	static char hex[] = "0123456789abcdef";
	return hex[code & 15];
}

/*---------------------------------------------------------------------------*/
/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char* url_encode(char* str) {
	char* pstr = str, * buf = malloc(strlen(str) * 3 + 1), * pbuf = buf;
	while (*pstr) {
		if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
			*pbuf++ = *pstr;
		else if (*pstr == ' ') {
			*pbuf++ = '+';
		}
		else
			*pbuf++ = '%', * pbuf++ = to_hex(*pstr >> 4), * pbuf++ = to_hex(*pstr & 15);
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}

/*---------------------------------------------------------------------------*/
/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char* url_decode(char* str) {
	char* pstr = str, * buf = malloc(strlen(str) + 1), * pbuf = buf;
	while (*pstr) {
		if (*pstr == '%') {
			if (pstr[1] && pstr[2]) {
				*pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
				pstr += 2;
			}
		}
		else if (*pstr == '+') {
			*pbuf++ = ' ';
		}
		else {
			*pbuf++ = *pstr;
		}
		pstr++;
	}
	*pbuf = '\0';
	return buf;
}

/*---------------------------------------------------------------------------*/
/* IMPORTANT: be sure to free() the returned string after use */
#define QUOT 	"&quot;"
#define AMP	 	"&amp;"
#define LT		"&lt;"
#define GT		"&gt;"
char* xml_encode(char* src)
{
	char* p, * q, * res;
	int i;

	for (i = 0, p = src; *p; p++) {
		switch (*p) {
		case '\"': i += strlen(QUOT); break;
		case '&':  i += strlen(AMP); break;
		case '<':  i += strlen(LT); break;
		case '>':  i += strlen(GT); break;
		}
	}

	res = malloc(strlen(src) + i + 1);
	if (!res) return NULL;

	for (q = res, p = src; *p; p++) {
		char* rep = NULL;
		switch (*p) {
		case '\"': rep = QUOT; break;
		case '&':  rep = AMP; break;
		case '<':  rep = LT; break;
		case '>':  rep = GT; break;
		}
		if (rep) {
			memcpy(q, rep, strlen(rep));
			q += strlen(rep);
		}
		else {
			*q = *p;
			q++;
		}
	}

	return res;
}
