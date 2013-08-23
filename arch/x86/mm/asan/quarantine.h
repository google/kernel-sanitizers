#ifndef ASAN_QUARANTINE_H_
#define ASAN_QUARANTINE_H_

#include <linux/slab.h>

struct chunk {
	struct kmem_cache *cache;
	void *object;
	struct list_head list;
};

void asan_quarantine_put(struct kmem_cache *cache, void *object);
void asan_quarantine_check(void);

#endif
