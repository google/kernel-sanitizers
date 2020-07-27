/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_KFENCE_H
#define _ASM_X86_KFENCE_H

#include <linux/kfence.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

/* TODO: Decide if we want huge page or 4k page on x86. */
#define KFENCE_POOL_ALIGNMENT PAGE_SIZE

/*
 * TODO: Clean this up.
 */

static pgprot_t pgprot_clear_protnone_bits(pgprot_t prot)
{
	/*
	 * _PAGE_GLOBAL means "global page" for present PTEs.
	 * But, it is also used to indicate _PAGE_PROTNONE
	 * for non-present PTEs.
	 *
	 * This ensures that a _PAGE_GLOBAL PTE going from
	 * present to non-present is not confused as
	 * _PAGE_PROTNONE.
	 */
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		pgprot_val(prot) &= ~_PAGE_GLOBAL;

	return prot;
}

/*
 * Some code borrowed from arch/x86/mm/pat/set_memory.c.
 * TODO(glider): need to figure out whether this code can be used on ARM64 and change it
 * accordingly.
 */
static bool split_large_page(pte_t *kpte, unsigned long address, unsigned int level)
{
	unsigned long lpaddr, lpinc, ref_pfn, pfn, pfninc = 1;
	pte_t *pbase;
	unsigned int i;
	pgprot_t ref_prot;
	struct page *base;

	base = alloc_pages(GFP_KERNEL, 0);
	if (!base)
		return false;
	pbase = (pte_t *)page_address(base);

	spin_lock(&pgd_lock);
	paravirt_alloc_pte(&init_mm, page_to_pfn(base));

	switch (level) {
	case PG_LEVEL_2M:
		ref_prot = pmd_pgprot(*(pmd_t *)kpte);
		/*
		 * Clear PSE (aka _PAGE_PAT) and move
		 * PAT bit to correct position.
		 */
		ref_prot = pgprot_large_2_4k(ref_prot);
		ref_pfn = pmd_pfn(*(pmd_t *)kpte);
		lpaddr = address & PMD_MASK;
		lpinc = PAGE_SIZE;
		break;

	case PG_LEVEL_1G:
		ref_prot = pud_pgprot(*(pud_t *)kpte);
		ref_pfn = pud_pfn(*(pud_t *)kpte);
		pfninc = PMD_PAGE_SIZE >> PAGE_SHIFT;
		lpaddr = address & PUD_MASK;
		lpinc = PMD_SIZE;
		/*
		 * Clear the PSE flags if the PRESENT flag is not set
		 * otherwise pmd_present/pmd_huge will return true
		 * even on a non present pmd.
		 */
		if (!(pgprot_val(ref_prot) & _PAGE_PRESENT))
			pgprot_val(ref_prot) &= ~_PAGE_PSE;
		break;

	default:
		spin_unlock(&pgd_lock);
		__free_page(base);
		return false;
	}

	ref_prot = pgprot_clear_protnone_bits(ref_prot);

	/*
	 * Get the target pfn from the original entry:
	 */
	pfn = ref_pfn;
	for (i = 0; i < PTRS_PER_PTE; i++, pfn += pfninc, lpaddr += lpinc)
		set_pte(pbase + i, pfn_pte(pfn, ref_prot));

	/*
	 * Install the new, split up pagetable.
	 *
	 * We use the standard kernel pagetable protections for the new
	 * pagetable protections, the actual ptes set above control the
	 * primary protection behavior:
	 */
	/*
	 * TODO(glider): for x86_32 see __set_pmd_pte() in
	 * arch/x86/mm/pat/set_memory.c
	 */
	set_pte_atomic(kpte, mk_pte(base, __pgprot(_KERNPG_TABLE)));

	/*
	 * Do a global flush tlb after splitting the large page
	 * and before we do the actual change page attribute in the PTE.
	 *
	 * Without this, we violate the TLB application note, that says:
	 * "The TLBs may contain both ordinary and large-page
	 *  translations for a 4-KByte range of linear addresses. This
	 *  may occur if software modifies the paging structures so that
	 *  the page size used for the address range changes. If the two
	 *  translations differ with respect to page frame or attributes
	 *  (e.g., permissions), processor behavior is undefined and may
	 *  be implementation-specific."
	 *
	 * We do this global tlb flush inside the cpa_lock, so that we
	 * don't allow any other cpu, with stale tlb entries change the
	 * page attribute in parallel, that also falls into the
	 * just split large page entry.
	 */
	flush_tlb_all();
	spin_unlock(&pgd_lock);

	return true;
}

static bool arch_kfence_initialize_pool(void)
{
	unsigned long addr = (unsigned long)__kfence_pool;

	while (is_kfence_addr((void *)addr)) {
		unsigned int level;
		pte_t *pte = lookup_address(addr, &level);

		if (!pte)
			return false;
		if (level == PG_LEVEL_4K) {
			addr += PAGE_SIZE;
			continue;
		}
		if (!split_large_page(pte, addr, level))
			return false;
	}
	flush_tlb_all();
	return true;
}

static bool kfence_change_page_prot(unsigned long addr, bool protect)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);
	pte_t new;

	if (!pte || level != PG_LEVEL_4K)
		return false;

	new = __pte(protect ? (pte_val(*pte) & ~_PAGE_PRESENT) : (pte_val(*pte) | _PAGE_PRESENT));
	set_pte(pte, new);

	/* TODO: figure out how to flush TLB properly here. */
	flush_tlb_one_kernel(addr);

	return true;
}

#endif /* _ASM_X86_KFENCE_H */
