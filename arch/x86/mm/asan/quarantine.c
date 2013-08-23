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
	struct asan_redzone *redzone = object + rounded_up_size;
	struct chunk *current_chunk = &redzone->chunk;

	if (!asan_enabled)
		return;

	current_chunk->cache = cache;
	current_chunk->object = object;

	spin_lock_irqsave(&lock, flags);

	list_add(&current_chunk->list, &chunk_list);
	quarantine_size += cache->object_size;

	spin_unlock_irqrestore(&lock, flags);
}

static int quarantine_check_in_progress; /* = 0; */

void asan_quarantine_check(void)
{
	struct chunk *chunk;
	struct kmem_cache *cache;
	void *object;

	if (quarantine_check_in_progress)
		return;
	quarantine_check_in_progress = 1;

	spin_lock_irqsave(&lock, flags);

	while (quarantine_size > ASAN_QUARANTINE_SIZE) {
		BUG_ON(list_empty(&chunk_list));

		chunk = list_entry(chunk_list.prev, struct chunk, list);
		list_del(chunk_list.prev);

		cache = chunk->cache;
		object = chunk->object;
		quarantine_size -= cache->object_size;

		/* XXX: unlock / lock. */
		spin_unlock_irqrestore(&lock, flags);
		kmem_cache_free(cache, object);
		spin_lock_irqsave(&lock, flags);
	}

	spin_unlock_irqrestore(&lock, flags);

	quarantine_check_in_progress = 0;
}
