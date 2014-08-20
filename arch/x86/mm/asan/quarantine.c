#include "asan.h"

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/smp.h>

/*
 * Free memory quarantine implementation.
 *
 * There is one main fifo queue, plus if SMP is enabled, one queue per CPU.
 * The queues are implemented as linked lists with struct redzone asumed
 * members.
 */


/** Queue of quarantined memory blocks */
struct q_queue {
	struct list_head list;  /** list of redzones */
	size_t size;            /** total size of blocks in queue */
	int initialized;
};

static struct q_queue global_queue;
static spinlock_t global_queue_lock = __SPIN_LOCK_UNLOCKED(global_queue_lock);

static DEFINE_PER_CPU(struct q_queue, percpu_queue);

/** Initializes the queue */
static void q_queue_init(struct q_queue *queue)
{
	BUG_ON(queue->initialized);
	INIT_LIST_HEAD(&queue->list);
	queue->size = 0;
	queue->initialized = 1;
}

/**
 * Adds an entry to head of the queue. Calculates the redzone to add based on
 * the parameters.
 * @queue: The queue to add to.
 * @cache: The cache where the object was allocated.
 * @object: Pointer to the freed memory.
 * */
static inline void q_queue_put(struct q_queue *queue, struct kmem_cache *cache,
		void *object)
{
	struct redzone *redzone;

	BUG_ON(!queue->initialized);
	BUG_ON(!ASAN_HAS_REDZONE(cache));
	redzone = ASAN_OBJECT_TO_REDZONE(cache, object);

	list_add(&redzone->quarantine_list, &queue->list);
	queue->size += cache->size;
}

/**
 * Removes an entry from the queue and moves it a given list
 * @queue: The queue to remove from.
 * @redzone: The entry to remove.
 * @list: The list to move the entry to.
 */
static inline void q_queue_remove(struct q_queue *queue,
		struct redzone *redzone, struct list_head *list)
{	struct kmem_cache *cache;

	BUG_ON(!queue->initialized);
	BUG_ON(list_empty(&queue->list));
	list_move(&redzone->quarantine_list, list);
	cache = virt_to_cache(redzone);
	queue->size -= cache->size;
}

/** Frees memory for all redzones in the list */
static inline void redzone_list_free(struct list_head *list)
{
	struct list_head *pos;
	struct redzone *redzone;
	struct kmem_cache *cache;
	void *object;

	list_for_each(pos, list) {
		redzone = list_entry(pos, struct redzone, quarantine_list);
		cache = virt_to_cache(redzone);
		object = ASAN_REDZONE_TO_OBJECT(cache, redzone);
		noasan_cache_free(cache, object, _THIS_IP_);
	}
}

/**
 * Transfers the entire from queue to the head of the to, leaving the from queue
 * empty
 */
static inline void q_queue_transfer(struct q_queue *from, struct q_queue *to)
{
	BUG_ON(!from->initialized || !to->initialized);
	list_splice_init(&from->list, &to->list);
	to->size += from->size;
	from->size = 0;
}

/** Initializes quarantine structures */
void __init asan_quarantine_init(void)
{
	q_queue_init(&global_queue);
}

/**
 * Transfers the per-cpu queue to the global queue. Then if the global queue
 * size is over ASAN_QUARANTINE_SIZE, reduces it to zero.
 */
static inline void quarantine_transfer_and_flush(q_queue *from)
{
	unsigned long flags;

	spin_lock_irqsave(&global_queue_lock, flags);

	q_queue_transfer(from, &global_queue);

	if (global_queue.size > ASAN_QUARANTINE_SIZE) {
		struct redzone *redzone;
		LIST_HEAD(to_free);

		while (global_queue.size > 0) {
			redzone = list_entry(global_queue.list.prev,
					struct redzone,
					quarantine_list);
			q_queue_remove(&global_queue, redzone, &to_free);
		}

		spin_unlock_irqrestore(&global_queue_lock, flags);

		local_irq_save(flags);
		redzone_list_free(&to_free);
		local_irq_restore(flags);
	} else {
		spin_unlock_irqrestore(&global_queue_lock, flags);
	}
}

/**
 * Puts the memory block to quarantine. If the per-cpu queue is larger then
 * treshold, transfers it to the main queue.
 */
void asan_quarantine_put(struct kmem_cache *cache, void *object)
{
	unsigned long flags;
	struct q_queue *q = get_cpu_var(percpu_queue);

	if (!q->initialized)
		q_queue_init(q);
	q_queue_put(q, cache, object);

	if (q->size > ASAN_QUARANTINE_SIZE / num_possible_cpus()) {
		struct q_queue temp;

		q_queue_init(&temp);
		q_queue_transfer(q, &temp);

		put_cpu_var(percpu_queue);

		quarantine_transfer_and_flush(&temp);
	} else {
		put_cpu_var(percpu_queue);
	}
}


/** Removes all blocks allocated in cache from queue. */
static inline void q_queue_drop_cache(struct q_queue *queue,
		struct kmem_cache *cache, struct list_head *to_free)
{
	struct list_head *pos, *temp;
	struct redzone *redzone;

	list_for_each_safe(pos, temp, &queue->list) {
		redzone = list_entry(pos, struct redzone, quarantine_list);
		if (virt_to_cache(redzone) == cache)
			q_queue_remove(queue, redzone, to_free);
	}
}

static void per_cpu_drop_cache(void *arg)
{
	struct kmem_cache *cache = (struct kmem_cache *) arg;
	LIST_HEAD(to_free);
	struct q_queue *q = &get_cpu_var(percpu_queue);

	BUG_ON(!irqs_disabled());

	if (q->initialized) {
		q_queue_drop_cache(q, cache, &to_free);
		redzone_list_free(&to_free);
	}
	put_cpu_var(percpu_queue);
}

/** Removes all blocks allocated in cache from quarantine. */
void asan_quarantine_drop_cache(struct kmem_cache *cache)
{
	unsigned long flags;
	LIST_HEAD(to_free);

	on_each_cpu(per_cpu_drop_cache, cache, 1);

	spin_lock_irqsave(&global_queue_lock, flags);
	q_queue_drop_cache(&global_queue, cache, &to_free);
	spin_unlock_irqrestore(&global_queue_lock, flags);

	local_irq_save(flags);
	redzone_list_free(&to_free);
	local_irq_restore(flags);
}

/** Returns the total size of memory in quarantine. No synchronization is used,
  * the result may be inconsistent. */
size_t asan_quarantine_size(void)
{
	size_t size = global_queue.size;
	int cpu;

	for_each_possible_cpu(cpu) {
		size += per_cpu(percpu_queue, cpu).size;
	}
	return size;
}
