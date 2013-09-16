#include <linux/asan.h>

#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/bug.h>
#include <asm/page.h>
#include <asm/thread_info.h>

#include "asan.h"
#include "report.h"
#include "test.h"

static int asan_enabled; /* = 0 */

static unsigned long quarantine_size; /* = 0; */
static LIST_HEAD(quarantine_chunk_list);
static DEFINE_SPINLOCK(quarantine_lock);

pid_t asan_get_current_thread_id(void)
{
	return current_thread_info()->task->pid;
}

static unsigned int asan_save_stack_trace(unsigned long *stack,
					  unsigned int max_entries)
{
	struct stack_trace trace_info = {
		.nr_entries = 0,
		.entries = stack,
		.max_entries = max_entries,
		/* Skip save_stack_trace() and asan_save_stack_trace(). */
		.skip = 2
	};
	save_stack_trace(&trace_info);
	return trace_info.nr_entries;
}

void asan_print_stack_trace(unsigned long *stack, unsigned int max_entries)
{
	unsigned int i;
	void *frame;

	for (i = 0; i < max_entries; i++) {
		if (stack[i] == ULONG_MAX || stack[i] == 0)
			break;
		frame = (void *)stack[i];
		pr_err("  #%u %p (%pS)\n", i, frame, frame);
	}
}

void asan_print_current_stack_trace(void)
{
	unsigned long stack[ASAN_MAX_STACK_TRACE_FRAMES];
	unsigned int entries =
		asan_save_stack_trace(&stack[0], ASAN_MAX_STACK_TRACE_FRAMES);
	asan_print_stack_trace(&stack[0], entries);
}

static void asan_quarantine_put(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->object_size;
	unsigned long rounded_up_size = round_up(size, SHADOW_GRANULARITY);
	struct asan_redzone *redzone = object + rounded_up_size;
	struct chunk *chunk = &redzone->chunk;
	unsigned long flags;

	if (!asan_enabled)
		return;

	spin_lock_irqsave(&quarantine_lock, flags);

	list_add(&chunk->list, &quarantine_chunk_list);
	quarantine_size += cache->object_size;

	spin_unlock_irqrestore(&quarantine_lock, flags);
}

static void asan_quarantine_check(void)
{
	struct chunk *chunk;
	struct kmem_cache *cache;
	void *object;
	unsigned long flags;

	spin_lock_irqsave(&quarantine_lock, flags);

	while (quarantine_size > ASAN_QUARANTINE_SIZE) {
		BUG_ON(list_empty(&quarantine_chunk_list));

		chunk = list_entry(quarantine_chunk_list.prev,
				   struct chunk, list);
		list_del(quarantine_chunk_list.prev);

		cache = chunk->cache;
		object = chunk->object;
		quarantine_size -= cache->object_size;

		/* XXX: unlock / lock. */
		spin_unlock_irqrestore(&quarantine_lock, flags);
		kmem_cache_free(cache, object);
		spin_lock_irqsave(&quarantine_lock, flags);
	}

	spin_unlock_irqrestore(&quarantine_lock, flags);
}

static bool asan_addr_is_in_mem(unsigned long addr)
{
	return (addr >= (unsigned long)(__va(0)) &&
		addr < (unsigned long)(__va(max_pfn << PAGE_SHIFT)));
}

unsigned long asan_mem_to_shadow(unsigned long addr)
{
	if (!asan_addr_is_in_mem(addr))
		return 0;
	return ((addr - PAGE_OFFSET) >> SHADOW_SCALE)
		+ PAGE_OFFSET + SHADOW_OFFSET;
}

unsigned long asan_shadow_to_mem(unsigned long shadow_addr)
{
	return ((shadow_addr - SHADOW_OFFSET - PAGE_OFFSET) << SHADOW_SCALE) +
	       PAGE_OFFSET;
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to SHADOW_GRANULARITY.
 */
static void asan_poison_shadow(const void *address, unsigned long size, u8 value)
{
	unsigned long shadow_beg, shadow_end;
	unsigned long addr = (unsigned long)address;

	BUG_ON(!IS_ALIGNED(addr, SHADOW_GRANULARITY));
	BUG_ON(!IS_ALIGNED(addr + size, SHADOW_GRANULARITY));
	BUG_ON(!asan_addr_is_in_mem(addr));
	BUG_ON(!asan_addr_is_in_mem(addr + size - SHADOW_GRANULARITY));

	shadow_beg = asan_mem_to_shadow(addr);
	shadow_end = asan_mem_to_shadow(addr + size - SHADOW_GRANULARITY) + 1;
	(memset)((void *)shadow_beg, value, shadow_end - shadow_beg);
}

static void asan_unpoison_shadow(const void *address, unsigned long size)
{
	asan_poison_shadow(address, size, 0);
}

static bool asan_memory_is_poisoned(unsigned long addr)
{
	const unsigned long ACCESS_SIZE = 1;
	u8 *shadow_addr = (u8 *)asan_mem_to_shadow(addr);
	s8 shadow_value = *shadow_addr;
	if (shadow_value != 0) {
		u8 last_accessed_byte = (addr & (SHADOW_GRANULARITY - 1))
					+ ACCESS_SIZE - 1;
		return last_accessed_byte >= shadow_value;
	}
	return false;
}

static bool asan_mem_is_zero(const u8 *beg, unsigned long size)
{
	const u8 *end = beg + size;
	unsigned long beg_addr = (unsigned long)beg;
	unsigned long end_addr = (unsigned long)end;
	unsigned long *aligned_beg =
		(unsigned long *)round_up(beg_addr, sizeof(unsigned long));
	unsigned long *aligned_end =
		(unsigned long *)round_down(end_addr, sizeof(unsigned long));
	unsigned long all = 0;
	const u8 *mem;
	for (mem = beg; mem < (u8 *)aligned_beg && mem < end; mem++)
		all |= *mem;
	for (; aligned_beg < aligned_end; aligned_beg++)
		all |= *aligned_beg;
	if ((u8 *)aligned_end >= beg)
		for (mem = (u8 *)aligned_end; mem < end; mem++)
			all |= *mem;
	return all == 0;
}

/*
 * Returns pointer to the first poisoned byte if the region is in memory
 * and poisoned, returns NULL otherwise.
 */
static const void *asan_region_is_poisoned(const void *addr, unsigned long size)
{
	unsigned long beg, end;
	unsigned long aligned_beg, aligned_end;
	unsigned long shadow_beg, shadow_end;

	if (size == 0)
		return NULL;

	beg = (unsigned long)addr;
	end = beg + size;
	if (!asan_addr_is_in_mem(beg) || !asan_addr_is_in_mem(end))
		return NULL;

	aligned_beg = round_up(beg, SHADOW_GRANULARITY);
	aligned_end = round_down(end, SHADOW_GRANULARITY);
	shadow_beg = asan_mem_to_shadow(aligned_beg);
	shadow_end = asan_mem_to_shadow(aligned_end);
	if (!asan_memory_is_poisoned(beg) &&
	    !asan_memory_is_poisoned(end - 1) &&
	    (shadow_end <= shadow_beg ||
	     asan_mem_is_zero((const u8 *)shadow_beg, shadow_end - shadow_beg)))
		return NULL;
	for (; beg < end; beg++)
		if (asan_memory_is_poisoned(beg))
			return (const void *)beg;

	BUG(); /* Unreachable. */
	return NULL;
}

void asan_check_region(const void *addr, unsigned long size, bool write)
{
	unsigned long poisoned_addr;

	if (!asan_enabled)
		return;

	poisoned_addr = (unsigned long)asan_region_is_poisoned(addr, size);

	if (poisoned_addr == 0)
		return;

	asan_report_error(poisoned_addr, size, write);
}

#define TSAN_REPORT(type, size, write)				\
void __tsan_##type##size(unsigned long addr)			\
{								\
	asan_check_region((void *)addr, (size), (write));	\
}								\
EXPORT_SYMBOL(__tsan_##type##size);

TSAN_REPORT(read, 1, false)
TSAN_REPORT(read, 2, false)
TSAN_REPORT(read, 4, false)
TSAN_REPORT(read, 8, false)
TSAN_REPORT(read, 16, false)

TSAN_REPORT(write, 1, true)
TSAN_REPORT(write, 2, true)
TSAN_REPORT(write, 4, true)
TSAN_REPORT(write, 8, true)
TSAN_REPORT(write, 16, true)

void __init asan_init_shadow(void)
{
	unsigned long shadow_size = (max_pfn << PAGE_SHIFT) >> SHADOW_SCALE;
	unsigned long found_free_range = memblock_find_in_range(SHADOW_OFFSET,
		SHADOW_OFFSET + shadow_size, shadow_size, SHADOW_GRANULARITY);
	void *shadow_beg = (void *)(PAGE_OFFSET + SHADOW_OFFSET);

	pr_err("Shadow offset: %x\n", SHADOW_OFFSET);
	pr_err("Shadow size: %lx\n", shadow_size);

	if (found_free_range != SHADOW_OFFSET ||
	    memblock_reserve(SHADOW_OFFSET, shadow_size) != 0) {
		pr_err("Error: unable to reserve shadow!\n");
		return;
	}

	/* XXX: use asan_unpoison_shadow()? */
	(memset)(shadow_beg, 0, shadow_size);
	asan_poison_shadow(shadow_beg, shadow_size, ASAN_SHADOW_GAP);

	asan_enabled = 1;
}

void asan_slab_create(struct kmem_cache *cache, void *slab)
{
	if (cache->flags & SLAB_DESTROY_BY_RCU)
		return;
	asan_poison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT,
			   ASAN_HEAP_REDZONE);
#if ASAN_QUARANTINE_ENABLE
	asan_quarantine_check();
#endif
}

void asan_slab_destroy(struct kmem_cache *cache, void *slab)
{
	asan_unpoison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT);
}

void asan_slab_alloc(struct kmem_cache *cache, void *object)
{
	unsigned long addr = (unsigned long)object;
	unsigned long size = cache->object_size;
	unsigned long rounded_down_size =
		round_down(size, SHADOW_GRANULARITY);
	unsigned long rounded_up_size =
		round_up(size, SHADOW_GRANULARITY);
	struct asan_redzone *redzone = object + rounded_up_size;
	unsigned long *alloc_stack = redzone->alloc_stack;
	u8 *shadow;

	/* FIXME: unpoison / poison. */
	asan_unpoison_shadow(alloc_stack, ASAN_STACK_TRACE_SIZE);
	asan_save_stack_trace(alloc_stack, ASAN_STACK_TRACE_FRAMES);
	asan_poison_shadow(alloc_stack, ASAN_STACK_TRACE_SIZE,
			   ASAN_HEAP_REDZONE);

	asan_unpoison_shadow(object, rounded_down_size);
	if (rounded_down_size != size) {
		shadow = (u8 *)asan_mem_to_shadow(addr + rounded_down_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}

	redzone->alloc_thread_id = asan_get_current_thread_id();
	redzone->free_thread_id = -1;

	redzone->chunk.cache = cache;
	redzone->chunk.object = object;

#if ASAN_QUARANTINE_ENABLE
	redzone->quarantine_flag = 0;
#endif

	redzone->kmalloc_size = 0;
}

bool asan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->object_size;
	unsigned long rounded_up_size = round_up(size, SHADOW_GRANULARITY);
	struct asan_redzone *redzone = object + rounded_up_size;
	unsigned long *free_stack = redzone->free_stack;

	if (cache->flags & SLAB_DESTROY_BY_RCU)
		return true;

#if ASAN_QUARANTINE_ENABLE
	/* Check if the object is in the quarantine. */
	if (redzone->quarantine_flag == 1)
		return true;
#endif

	asan_poison_shadow(object, rounded_up_size, ASAN_HEAP_FREE);

	/* FIXME: unpoison / poison. */
	asan_unpoison_shadow(free_stack, ASAN_STACK_TRACE_SIZE);
	asan_save_stack_trace(free_stack, ASAN_STACK_TRACE_FRAMES);
	asan_poison_shadow(free_stack, ASAN_STACK_TRACE_SIZE,
			   ASAN_HEAP_REDZONE);

	redzone->free_thread_id = asan_get_current_thread_id();

#if ASAN_QUARANTINE_ENABLE
	asan_quarantine_put(cache, object);
	redzone->quarantine_flag = 1;
	return false;
#endif

	return true;
}

void asan_kmalloc(struct kmem_cache *cache, void *object, unsigned long size)
{
	unsigned long addr = (unsigned long)object;
	unsigned long object_size = cache->object_size;
	unsigned long rounded_up_object_size =
		round_up(object_size, SHADOW_GRANULARITY);
	unsigned long rounded_down_kmalloc_size =
		round_down(size, SHADOW_GRANULARITY);
	struct asan_redzone *redzone = object + rounded_up_object_size;
	u8 *shadow;

	if (object == NULL)
		return;

	asan_poison_shadow(object, rounded_up_object_size,
			   ASAN_HEAP_KMALLOC_REDZONE);
	asan_unpoison_shadow(object, rounded_down_kmalloc_size);
	if (rounded_down_kmalloc_size != size) {
		shadow = (u8 *)asan_mem_to_shadow(addr +
						  rounded_down_kmalloc_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}

	redzone->kmalloc_size = size;
}
EXPORT_SYMBOL(asan_kmalloc);

void asan_krealloc(void *object, unsigned long new_size)
{
	struct page *page = virt_to_head_page(object);
	struct kmem_cache *cache = page->slab_cache;
	asan_kmalloc(cache, object, new_size);
}

void asan_add_redzone(struct kmem_cache *cache, size_t *cache_size)
{
	unsigned long object_size = cache->object_size;
	unsigned long rounded_up_object_size =
		round_up(object_size, sizeof(unsigned long));

	/* FIXME: no redzones in 4MB cache. */
	if (*cache_size >= 4 * 1024 * 1024) {
		pr_err("Warning: unable to add redzones for cache with size: %lu.\n",
		       *cache_size);
		return;
	}

	*cache_size += ASAN_REDZONE_SIZE;
	cache->asan_has_redzone = 1;

	/* Ensure that the cache is large enough. */
	BUG_ON(*cache_size < rounded_up_object_size + ASAN_REDZONE_SIZE);
}

void asan_on_kernel_init(void)
{
	/*asan_do_bo();
	asan_do_bo_left();
	asan_do_bo_kmalloc();
	asan_do_bo_krealloc();
	asan_do_bo_krealloc_less();
	asan_do_bo_16();
	asan_do_krealloc_more();
	asan_do_uaf();
	asan_do_uaf_quarantine();*/
	asan_do_uaf_memset();
}
