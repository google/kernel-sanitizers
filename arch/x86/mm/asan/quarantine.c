#include "quarantine.h"

#include "asan.h"

#include <linux/list.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h> 
#include <asm-generic/atomic-long.h>


struct q_queue {
	spinlock_t lock;
	struct list_head list;
	atomic_long_t size;
};

struct q_queue global_queue;
int percpu_enabled = 0;
DEFINE_PER_CPU(struct q_queue, percpu_queue);

static void q_queue_init(struct q_queue* queue)
{
	pr_err("q_queue init %p\n", queue);
	spin_lock_init(&queue->lock);
	INIT_LIST_HEAD(&queue->list);
	atomic_long_set(&queue->size, 0);
}

// Adds an entry to head of the queue.
static void q_queue_put(struct q_queue* queue, struct kmem_cache* cache,
		void* object) 
{
	struct redzone *redzone;
	unsigned long flags;

	BUG_ON(!ASAN_HAS_REDZONE(cache));
	redzone = ASAN_OBJECT_TO_REDZONE(cache, object);

	spin_lock_irqsave(&queue->lock, flags);
	list_add(&redzone->quarantine_list, &queue->list);
	atomic_long_add(cache->size, &queue->size);
	spin_unlock_irqrestore(&queue->lock, flags);
}

// Removes an entry from the queue.
//
// Since we often need to remove several entries, this function doesn't
// lock the spinlock, instead assuming it has already been locked. It
// is also locked after return.
static void q_queue_remove(struct q_queue* queue, struct redzone* redzone,
		unsigned long* flags)
{
	struct kmem_cache *cache;
	void *object;

	BUG_ON(list_empty(&queue->list));

	list_del(&redzone->quarantine_list);

	cache = virt_to_cache(redzone);
	object = ASAN_REDZONE_TO_OBJECT(cache, redzone);

	atomic_long_sub(cache->size, &queue->size);

	spin_unlock_irqrestore(&queue->lock, *flags);
	local_irq_save(*flags);
	noasan_cache_free(cache, object, _THIS_IP_);
	local_irq_restore(*flags);
	spin_lock_irqsave(&queue->lock, *flags);
}

// Transfers the entire from queue to the head of the to, leaving the from queue
// empty
static void q_queue_transfer(struct q_queue* from, struct q_queue* to)
{
	unsigned long flags;
	LIST_HEAD(temp);
	size_t size;

	pr_err("q_queue %p transfer to %p\n", from, to);
	spin_lock_irqsave(&from->lock, flags);
	size = atomic_long_read(&from->size);
	list_move(&from->list, &temp);
	atomic_long_set(&from->size, 0);
	INIT_LIST_HEAD(&from->list);
	spin_unlock_irqrestore(&from->lock, flags);
	
	spin_lock_irqsave(&to->lock, flags);
	list_move(&temp, &to->list);
	atomic_long_add(size, &to->size);
	spin_unlock_irqrestore(&to->lock, flags);
	pr_err("q_queue transfered %ld bytes\n", size);
}

static int try_init_percpu(void)
{
	int cpu;
	unsigned long flags;

	if (percpu_enabled) {
		return 1;
	}
	if (num_possible_cpus() < 2) {
		return 0;
	}

	spin_lock_irqsave(&global_queue.lock, flags);
	if (!percpu_enabled) {
		for_each_possible_cpu(cpu) {
			q_queue_init(&per_cpu(percpu_queue, cpu));
		}
		percpu_enabled = 1;
	}
	spin_unlock_irqrestore(&global_queue.lock, flags);
	return 1;
}


void __init asan_quarantine_init(void)
{
	q_queue_init(&global_queue);
	try_init_percpu();
}

void asan_quarantine_put(struct kmem_cache *cache, void *object)
{
	if (try_init_percpu()) {
		struct q_queue* q = &get_cpu_var(percpu_queue);
		q_queue_put(q, cache, object);
		if (atomic_long_read(&q->size) >
				ASAN_QUARANTINE_SIZE / num_possible_cpus()) {
			q_queue_transfer(q, &global_queue);
		}
	} else {
		q_queue_put(&global_queue, cache, object);
	}
}

static inline size_t global_size(void)
{
	return atomic_long_read(&global_queue.size);
}

void asan_quarantine_flush(void)
{
	if (try_init_percpu() 
			&& global_size() > ASAN_QUARANTINE_SIZE
			&& asan_quarantine_size() > ASAN_QUARANTINE_SIZE * 2) {
		int cpu;
		for_each_possible_cpu(cpu) {
			q_queue_transfer(&per_cpu(percpu_queue, cpu),
					&global_queue);
		}
	}
	if (global_size() > ASAN_QUARANTINE_SIZE * 2) {
		unsigned long flags;
		struct redzone* redzone;

		spin_lock_irqsave(&global_queue.lock, flags);

		while (global_size() > ASAN_QUARANTINE_SIZE) {
			redzone = list_entry(global_queue.list.prev,
					struct redzone, quarantine_list);
			q_queue_remove(&global_queue, redzone,
					&flags);			
		}
		
		spin_unlock_irqrestore(&global_queue.lock, flags);
	}
}

static void q_queue_drop_cache(struct q_queue* q, struct kmem_cache* cache)
{
	struct list_head *pos, *temp;
	struct redzone *redzone;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);

	list_for_each_safe(pos, temp, &q->list) {
		redzone = list_entry(pos, struct redzone, quarantine_list);
		if (virt_to_cache(redzone) == cache) {
			q_queue_remove(q, redzone, &flags);
		}
	}

	spin_unlock_irqrestore(&q->lock, flags);
}

void asan_quarantine_drop_cache(struct kmem_cache *cache)
{
	if (try_init_percpu()) {
		int cpu;

		for_each_possible_cpu(cpu) {
			q_queue_drop_cache(&per_cpu(percpu_queue, cpu), cache);
		}
	}

	q_queue_drop_cache(&global_queue, cache);
}

size_t asan_quarantine_size()
{
	size_t size = global_size();
	if (try_init_percpu()) {
		int cpu;

		for_each_possible_cpu(cpu) {
			size += atomic_long_read(&per_cpu(
					percpu_queue, cpu).size);
		}
	}
	return size;
}
