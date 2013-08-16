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

#include "stack.h"

void asan_slab_alloc(struct kmem_cache *cache, void *object)
{
	unsigned long addr = (unsigned long)object;
	unsigned long size = cache->object_size;
	unsigned long rounded_down_size =
		round_down_to(size, SHADOW_GRANULARITY);
	//unsigned long rounded_up_size = 
	//	round_up_to(size, SHADOW_GRANULARITY);
	u8 *shadow;

	asan_unpoison_shadow(object, rounded_down_size);
	if (rounded_down_size != size) {
		shadow = (u8 *)mem_to_shadow(addr + rounded_down_size);
		*shadow = size & (SHADOW_GRANULARITY - 1);
	}

	/*u8 *quarantine_flag = (u8 *)(object + size);
	*quarantine_flag = 0;*/
}

bool asan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->object_size;
	unsigned long rounded_up_size = round_up_to(size, SHADOW_GRANULARITY);

	if (cache->flags & SLAB_DESTROY_BY_RCU)
		return true;

	asan_poison_shadow(object, rounded_up_size, ASAN_HEAP_FREE);

	asan_unpoison_shadow(object + rounded_up_size, ASAN_REDZONE_SIZE);
	asan_save_stack((unsigned long *)(object + rounded_up_size),
			ASAN_REDZONE_SIZE / sizeof(unsigned long));
	asan_poison_shadow(object + rounded_up_size, ASAN_REDZONE_SIZE,
			   ASAN_HEAP_REDZONE);

	/*u8 *quarantine_flag = (u8 *)(object + size);
	if (*quarantine_flag == 0) {
		asan_poison_shadow(object, rounded_up_size, ASAN_HEAP_FREE);

		*quarantine_flag = 1;
		asan_quarantine_put(cache, object);
		asan_quarantine_check();

		return false;
	}*/

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
