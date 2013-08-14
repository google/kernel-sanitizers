#ifndef ASAN_QUARANTINE_H_
#define ASAN_QUARANTINE_H_

#include <linux/types.h>
#include <linux/slab.h>

void asan_quarantine_put(struct kmem_cache *cache, void *object);
void asan_quarantine_get(struct kmem_cache **cache, void **object);
void asan_quarantine_check(void);

#endif
