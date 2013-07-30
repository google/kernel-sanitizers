#include <asm/page.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <linux/asan.h>

#include "error.h"
#include "mapping.h"
#include "poisoning.h"
#include "report.h"
#include "utils.h"

int asan_enabled; /* = 0 */

void asan_init_shadow(void)
{
	unsigned long shadow_size = (max_pfn << PAGE_SHIFT) >> SHADOW_SCALE;
	pr_err("Shadow offset: %x\n", SHADOW_OFFSET);
	pr_err("Shadow size: %lx\n", shadow_size);
	if (memblock_reserve(SHADOW_OFFSET, shadow_size) != 0) {
		pr_err("Error: unable to reserve shadow!\n");
		return;
	}
	memset((void *)(PAGE_OFFSET + SHADOW_OFFSET), 0, shadow_size);
	asan_enabled = 1;
}

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

void asan_slab_create(const struct kmem_cache *cache, const void *slab)
{
	if (!(cache->flags & SLAB_DESTROY_BY_RCU))
		asan_poison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT,
				   ASAN_HEAP_FREE);
}

void asan_slab_destroy(const struct kmem_cache *cache, const void *slab)
{
	asan_unpoison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT);
}

void asan_slab_alloc(const struct kmem_cache *cache, const void *object)
{
	if (cache->asan_redzones)
		asan_poison_shadow(object + cache->object_size,
				   ASAN_REDZONE_SIZE, ASAN_HEAP_REDZONE);
	asan_unpoison_shadow(object, cache->object_size);
}

void asan_slab_free(const struct kmem_cache *cache, const void *object)
{
	if (!(cache->flags & SLAB_DESTROY_BY_RCU))
		asan_poison_shadow(object, cache->object_size, ASAN_HEAP_FREE);
}

static void run_tests(void)
{
	unsigned long i;

	pr_err("Running tests...\n");

	BUG_ON(asan_region_is_poisoned((void *)PAGE_OFFSET, 50) != NULL);

	asan_poison_memory((void *)(PAGE_OFFSET + 5), 27);
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + 5; i++)
		BUG_ON(asan_memory_is_poisoned(i));
	for (i = PAGE_OFFSET + 5;
	     i < round_down_to(PAGE_OFFSET + 5 + 27, SHADOW_GRANULARITY);
	     i++) {
		BUG_ON(!asan_memory_is_poisoned(i));
	}
	for (i = PAGE_OFFSET + 5 + 27; i < PAGE_OFFSET + 50; i++)
		BUG_ON(asan_memory_is_poisoned(i));

	BUG_ON(asan_region_is_poisoned((void *)PAGE_OFFSET, 50)
	      != (void *)(PAGE_OFFSET + 5));
	BUG_ON(asan_region_is_poisoned((void *)(PAGE_OFFSET + 10), 50)
	      != (void *)(PAGE_OFFSET + 10));

	asan_unpoison_memory((void *)(PAGE_OFFSET + 5), 27);
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + 50; i++)
		BUG_ON(asan_memory_is_poisoned(i));

	BUG_ON(asan_region_is_poisoned((void *)PAGE_OFFSET, 50) != NULL);

	asan_poison_shadow((void *)(PAGE_OFFSET + SHADOW_GRANULARITY),
			   SHADOW_GRANULARITY * 5, ASAN_HEAP_FREE);
	BUG_ON(asan_region_is_poisoned((void *)PAGE_OFFSET,
				      SHADOW_GRANULARITY * 3) !=
	      (void *)(PAGE_OFFSET + SHADOW_GRANULARITY));
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + SHADOW_GRANULARITY; i++)
		BUG_ON(asan_memory_is_poisoned(i));
	for (i = PAGE_OFFSET + SHADOW_GRANULARITY;
	     i < PAGE_OFFSET + SHADOW_GRANULARITY * 6; i++) {
		BUG_ON(!asan_memory_is_poisoned(i));
	}
	for (i = PAGE_OFFSET + SHADOW_GRANULARITY * 6;
	    i < PAGE_OFFSET + SHADOW_GRANULARITY * 10; i++) {
		BUG_ON(asan_memory_is_poisoned(i));
	}

	asan_poison_shadow((void *)(PAGE_OFFSET + SHADOW_GRANULARITY),
		   SHADOW_GRANULARITY * 5, 0);
	for (i = PAGE_OFFSET; i < PAGE_OFFSET + SHADOW_GRANULARITY * 10; i++)
		BUG_ON(asan_memory_is_poisoned(i));

	pr_err("Passed all the tests.\n");
}

void asan_on_kernel_init(void)
{
	run_tests();
	do_use_after_free();
	do_access_redzone();
}

void asan_on_memcpy(const void *to, const void *from, unsigned long n)
{
	if (!asan_enabled)
		return;

	/* asan_check_region(to, n);
	   asan_check_region(from, n); */
}
EXPORT_SYMBOL_GPL(asan_on_memcpy);
