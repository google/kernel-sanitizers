#include "quarantine.h"

#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "internal.h"
#include "utils.h"

/* FIXME: chunks_list. */
static LIST_HEAD(chunk_list);
static unsigned long quarantine_size; /* = 0; */

static DEFINE_SPINLOCK(lock);
static unsigned long flags;

void asan_quarantine_put(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->object_size;
	unsigned long rounded_up_size = round_up_to(size, SHADOW_GRANULARITY);
	struct chunk *current_chunk = object + rounded_up_size +
				      ASAN_REDZONE_SIZE - sizeof(struct chunk);

	if (!asan_enabled)
		return;

	BUG_ON(!current_chunk);
	current_chunk->cache = cache;
	current_chunk->object = object;

	spin_lock_irqsave(&lock, flags);

	list_add(&(current_chunk->list), &chunk_list);
	quarantine_size += cache->object_size;

	spin_unlock_irqrestore(&lock, flags);
}

static void asan_quarantine_get(struct kmem_cache **cache, void **object)
{
	struct chunk *current_chunk;

	BUG_ON(list_empty(&chunk_list));

	current_chunk = list_entry(chunk_list.prev, struct chunk, list);
	*cache = current_chunk->cache;
	*object = current_chunk->object;
	quarantine_size -= current_chunk->cache->object_size;
	list_del(chunk_list.prev);
}

int quarantine_check_in_progress; /* = 0; */

void asan_quarantine_check(void)
{
	struct kmem_cache *cache;
	void *object;

	if (quarantine_check_in_progress)
		return;
	quarantine_check_in_progress = 1;

	spin_lock_irqsave(&lock, flags);

	while (quarantine_size > ASAN_QUARANTINE_SIZE) {
		asan_quarantine_get(&cache, &object);

		/* XXX: unlock / lock. */
		spin_unlock_irqrestore(&lock, flags);
		kmem_cache_free(cache, object);
		spin_lock_irqsave(&lock, flags);
	}

	spin_unlock_irqrestore(&lock, flags);

	quarantine_check_in_progress = 0;
}
