/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_KFENCE_H
#define _ASM_X86_KFENCE_H

#include <linux/bug.h>
#include <linux/kfence.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>

/* The alignment should be at least a 4K page. */
#define __kfence_pool_attrs __aligned(PAGE_SIZE)

/*
 * The page fault handler entry function, up to which the stack trace is
 * truncated in reports.
 */
#define KFENCE_SKIP_ARCH_FAULT_HANDLER "asm_exc_page_fault"

/* Force 4K pages for __kfence_pool. */
static inline bool arch_kfence_initialize_pool(void)
{
	unsigned long addr;

	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
	     addr += PAGE_SIZE) {
		unsigned int level;

		if (!lookup_address(addr, &level))
			return false;

		if (level != PG_LEVEL_4K)
			set_memory_4k(addr, 1);
	}

	return true;
}

/* Protect the given page and flush TLB. */
static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	struct page *page = virt_to_page(addr);

	if (!pte || level != PG_LEVEL_4K)
		return false;

	/*
	 * We need to avoid IPIs, as we may get KFENCE allocations or faults
	 * with interrupts disabled. Therefore, the below is best-effort, and
	 * does not flush TLBs on all CPUs. We can tolerate some inaccuracy;
	 * lazy fault handling takes care of faults after the page is PRESENT.
	 */

	if (protect)
		set_direct_map_invalid_noflush(page);
	else
		set_direct_map_default_noflush(page);

	/* Flush this CPU's TLB. */
	flush_tlb_one_kernel(addr);
	return true;
}

#endif /* _ASM_X86_KFENCE_H */
