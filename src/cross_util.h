/*
 * Misc utilities
 *
 * (c) Philippe, philippe_44@outlook.com
 *
 * See LICENSE file
 *
 */

#pragma once

#include <stdint.h>
#if __has_include("pthread.h")
#include "pthread.h"
#define HAS_PTHREAD
#else 
#endif

#include "platform.h"

#define NFREE(p) do {	\
	if (p) {			\
		free(p);		\
		p = NULL;		\
	}					\
} while (0)

/*
Queues
*/
typedef struct {
#ifdef HAS_PTHREAD
	pthread_mutex_t* mutex;
#elif defined(_WIN32)
	HANDLE* mutex;
#else 
	void* mutex;
#endif
	void (*cleanup)(void*);
	struct _queue_s {
		struct _queue_s* next;
		void* item;
	} list;
} queue_t;

void	queue_init(queue_t *queue, bool mutex, void (*f)(void*));
void	queue_insert(queue_t *queue, void *item);
void*	queue_extract(queue_t *queue);
void	queue_flush(queue_t *queue);
void	queue_free_item(queue_t* queue, void* item);

/*
Linked lists
*/
typedef struct list_s {
	struct list_s* next;
} list_t;

list_t*		list_push(list_t *item, list_t **list);
list_t*		list_add_tail(list_t *item, list_t **list);
list_t*		list_add_ordered(list_t *item, list_t **list, int (*compare)(void *a, void *b));
list_t*		list_pop(list_t **list);
list_t*   	list_remove(list_t *item, list_t **list);
void 		list_clear(list_t **list, void (*free_func)(void *));

/* 
Key-Value tools
*/
typedef struct key_data_s {

	char *key;
	char *data;
} key_data_t;

char*		kd_lookup(key_data_t *kd, char *key);
bool 		kd_add(key_data_t *kd, char *key, char *value);
bool 		kd_vadd(key_data_t *kd, char *key, char *fmt, ...);
char* 		kd_dump(key_data_t *kd);
void 		kd_free(key_data_t *kd);

/*
String tools
*/
char* strextract(char* s1, char* beg, char* end);
char* strltrim(char* s);
char* strrtrim(char* s);
char* strtrim(char* s);
int   strremovechar(char* str, char c);

/*
WWW tools
*/
char* url_encode(char* str);
char* url_decode(char* str);
char* xml_encode(char* src);

/*
Kitchen sink
*/
uint32_t	gettime_ms(void);
uint64_t 	gettime_ms64(void);
uint32_t	hash32(char* str);
int			hex2bytes(char* hex, uint8_t** bytes);
void		touch_memory(uint8_t* buf, size_t size);
