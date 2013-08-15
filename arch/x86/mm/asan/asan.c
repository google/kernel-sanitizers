#include <asm/page.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <linux/asan.h>

#include "error.h"
#include "mapping.h"
#include "poisoning.h"
#include "quarantine.h"
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
	if (cache->flags & SLAB_DESTROY_BY_RCU)
		return;
	asan_poison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT,
			   ASAN_HEAP_REDZONE);
}

void asan_slab_destroy(const struct kmem_cache *cache, const void *slab)
{
	asan_unpoison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT);
}

void asan_slab_alloc(const struct kmem_cache *cache, const void *object)
{
	unsigned long addr = (unsigned long)object;
	unsigned long size = cache->object_size;
	unsigned long rounded_size = round_down_to(size, SHADOW_GRANULARITY);
	u8 *shadow;
	u8 *quarantine_flag = (u8 *)(object + size);

	asan_unpoison_shadow(object, rounded_size);
	if (rounded_size != size) {
		shadow = (u8 *)mem_to_shadow(addr + rounded_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}

	*quarantine_flag = 0;
}

bool asan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size;
	u8 *quarantine_flag;

	if (cache->flags & SLAB_DESTROY_BY_RCU)
		return true;

	size = round_up_to(cache->object_size, SHADOW_GRANULARITY);
	quarantine_flag = (u8 *)(object + size);

	if (*quarantine_flag == 0) {
		asan_poison_shadow(object, size, ASAN_HEAP_FREE);
		return true; // tmp
		*quarantine_flag = 1;
		asan_quarantine_put(cache, object);
		asan_quarantine_check();

		return false;
	}

	return true;
}

/* FIXME: optimize. */
void asan_kmalloc(const struct kmem_cache *cache, const void *object,
		  unsigned long size)
{
	unsigned long addr = (unsigned long)object;
	unsigned long object_size = cache->object_size;
	unsigned long rounded_up_object_size =
		round_up_to(object_size, SHADOW_GRANULARITY);
	unsigned long rounded_down_size =
		round_down_to(size, SHADOW_GRANULARITY);
	u8 *shadow;

	if (object == NULL)
		return;

	asan_poison_shadow(object, rounded_up_object_size, ASAN_HEAP_REDZONE);
	asan_unpoison_shadow(object, rounded_down_size);
	if (rounded_down_size != size) {
		shadow = (u8 *)mem_to_shadow(addr + rounded_down_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}
}

#include <linux/mm.h>

/* FIXME: optimize. */
void asan_krealloc(const void *object, unsigned long new_size)
{
	struct page *page = virt_to_head_page(object);
	struct kmem_cache *cache = page->slab_cache;
	asan_kmalloc(cache, object, new_size);
}

void asan_on_kernel_init(void)
{
	do_uaf_memset();
}
