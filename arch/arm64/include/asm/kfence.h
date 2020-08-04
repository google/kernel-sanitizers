/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ASM_KFENCE_H
#define __ASM_KFENCE_H

#include <linux/kfence.h>
#include <linux/log2.h>
#include <linux/mm.h>

#include <asm/cacheflush.h>

#define KFENCE_SKIP_ARCH_FAULT_HANDLER "el1_sync"

/*
 * FIXME: Support HAVE_ARCH_KFENCE_STATIC_POOL: Use the statically allocated
 * __kfence_pool, to avoid the extra pointer load for is_kfence_address(). By
 * default, however, we do not have struct pages for static allocations.
 */

static inline bool arch_kfence_initialize_pool(void)
{
	const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
	struct page *pages = alloc_pages(GFP_KERNEL, num_pages);

	if (!pages)
		return false;

	__kfence_pool = page_address(pages);
	return true;
}

static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	set_memory_valid(addr, 1, !protect);

	return true;
}

#endif /* __ASM_KFENCE_H */
