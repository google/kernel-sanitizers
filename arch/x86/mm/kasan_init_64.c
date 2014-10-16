#include <linux/bootmem.h>
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/tlbflush.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern struct range pfn_mapped[E820_X_MAX];

struct vm_struct kasan_vm __initdata = {
	.addr = (void *)KASAN_SHADOW_START,
	.size = (16UL << 40),
};


static int __init map_range(struct range *range)
{
	unsigned long start = kasan_mem_to_shadow(
		(unsigned long)pfn_to_kaddr(range->start));
	unsigned long end = kasan_mem_to_shadow(
		(unsigned long)pfn_to_kaddr(range->end));

	/*
	 * end + 1 here is intentional. We check several shadow bytes in advance
	 * to slightly speed up fastpath. In some rare cases we could cross
	 * boundary of mapped shadow, so we just map some more here.
	 */
	return vmemmap_populate(start, end + 1, NUMA_NO_NODE);
}

static void __init clear_zero_shadow_mapping(unsigned long start,
					unsigned long end)
{
	for (; start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}

void __init kasan_map_zero_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = kasan_mem_to_shadow(KASAN_SHADOW_START);

	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(zero_pud) | __PAGE_KERNEL_RO);
		start += PGDIR_SIZE;
	}

	start = end;
	end = kasan_mem_to_shadow(KASAN_SHADOW_END);
	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(poisoned_pud) | __PAGE_KERNEL_RO);
		start += PGDIR_SIZE;
	}

	start = end;
	end = KASAN_SHADOW_END;
	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(zero_pud) | __PAGE_KERNEL_RO);
		start += PGDIR_SIZE;
	}

}

void __init kasan_map_shadow(void)
{
	int i;

	vm_area_add_early(&kasan_vm);

	memcpy(early_level4_pgt, init_level4_pgt, sizeof(early_level4_pgt));
	load_cr3(early_level4_pgt);

	clear_zero_shadow_mapping(kasan_mem_to_shadow(PAGE_OFFSET),
				kasan_mem_to_shadow(PAGE_OFFSET + MAXMEM));

	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		if (map_range(&pfn_mapped[i]))
			panic("kasan: unable to allocate shadow!");
	}
	load_cr3(init_level4_pgt);
}
