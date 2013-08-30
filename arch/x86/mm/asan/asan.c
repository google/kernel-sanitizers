#include <linux/asan.h>

#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/page.h>

#include "internal.h"
#include "mapping.h"
#include "poisoning.h"
#include "quarantine.h"
#include "report.h"
#include "sample_errors.h"
#include "stack_trace.h"
#include "thread.h"

int asan_enabled; /* = 0 */

/* XXX: move to another file? */
void asan_check_region(const void *addr, unsigned long size)
{
	unsigned long poisoned_addr;

	if (!asan_enabled)
		return;

	poisoned_addr = (unsigned long)asan_region_is_poisoned(addr, size);

	if (poisoned_addr == 0)
		return;

	asan_report_error(poisoned_addr);
}

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
	asan_quarantine_check();
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
		ROUND_DOWN_TO(size, SHADOW_GRANULARITY);
	unsigned long rounded_up_size =
		ROUND_UP_TO(size, SHADOW_GRANULARITY);
	struct asan_redzone *redzone = object + rounded_up_size;
	unsigned long *alloc_stack = redzone->alloc_stack;
	u8 *shadow;

	/* FIXME: unpoison / poison. */
	asan_unpoison_shadow(alloc_stack, ASAN_STACK_TRACE_SIZE);
	asan_save_stack_trace(alloc_stack, ASAN_FRAMES_IN_STACK_TRACE);
	asan_poison_shadow(alloc_stack, ASAN_STACK_TRACE_SIZE,
			   ASAN_HEAP_REDZONE);

	asan_unpoison_shadow(object, rounded_down_size);
	if (rounded_down_size != size) {
		shadow = (u8 *)mem_to_shadow(addr + rounded_down_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}

	redzone->alloc_thread_id = get_current_thread_id();
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
	unsigned long rounded_up_size = ROUND_UP_TO(size, SHADOW_GRANULARITY);
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
	asan_save_stack_trace(free_stack, ASAN_FRAMES_IN_STACK_TRACE);
	asan_poison_shadow(free_stack, ASAN_STACK_TRACE_SIZE,
			   ASAN_HEAP_REDZONE);

	redzone->free_thread_id = get_current_thread_id();

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
		ROUND_UP_TO(object_size, SHADOW_GRANULARITY);
	unsigned long rounded_down_kmalloc_size =
		ROUND_DOWN_TO(size, SHADOW_GRANULARITY);
	struct asan_redzone *redzone = object + rounded_up_object_size;
	u8 *shadow;

	if (object == NULL)
		return;

	asan_poison_shadow(object, rounded_up_object_size,
			   ASAN_HEAP_KMALLOC_REDZONE);
	asan_unpoison_shadow(object, rounded_down_kmalloc_size);
	if (rounded_down_kmalloc_size != size) {
		shadow = (u8 *)mem_to_shadow(addr + rounded_down_kmalloc_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}

	redzone->kmalloc_size = size;
}

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
		ROUND_UP_TO(object_size, sizeof(unsigned long));

	/* FIXME: no redzones in 4MB cache. */
	if (*cache_size >= 4 * 1024 * 1024) {
		pr_err("Warning: unable to add redzones for cache with size: %lu.\n",
		       *cache_size);
		return;
	}

	*cache_size += ASAN_REDZONE_SIZE;
	cache->asan_redzones = 1;

	/* Ensure that the cache is large enough. */
	BUG_ON(*cache_size < rounded_up_object_size + ASAN_REDZONE_SIZE);
}

void asan_on_kernel_init(void)
{
	/*do_bo();
	do_bo_left();
	do_bo_kmalloc();
	do_bo_krealloc();
	do_uaf();
	do_uaf_quarantine();*/
	do_uaf_memset();
}
