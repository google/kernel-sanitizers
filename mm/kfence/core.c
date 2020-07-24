// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "kfence: " fmt

#include <linux/debugfs.h>
#include <linux/kfence.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include "kfence.h"

unsigned long kfence_sample_rate = CONFIG_KFENCE_SAMPLE_RATE;

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
module_param_named(sample_rate, kfence_sample_rate, ulong, 0444);

/* Usually on, unless explicitly disabled. */
bool kfence_enabled;

struct kfence_freelist {
	struct list_head list;
	void *obj;
};

char __kfence_pool_start[PAGE_SIZE << (KFENCE_NUM_OBJ_LOG + 1)] __aligned(2 << 21);
EXPORT_SYMBOL(__kfence_pool_start);

/* Protects kfence_freelist, kfence_recycle, kfence_metadata */
static DEFINE_SPINLOCK(kfence_alloc_lock);

/*
 * kfence_freelist is a wrapper around kfence page pointers that allows
 * chaining them.
 * @kfence_freelist is a FIFO queue of non-allocated pages, @kfence_recycle is
 * a stack of unused kfence_freelist objects.
 * When allocating a new object in kfence_guarded_alloc(), a kfence_freelist
 * item is taken from the queue and its @kfence_freelist.obj member is used for
 * allocation. The item is put into @kfence_recycle - at this point its contents
 * aren't valid anymore.
 * When freeing an object, it is wrapped into a kfence_freelist taken from
 * @kfence_recycle. This kfence_freelist item is placed at the end of
 * @kfence_freelist to delay the reuse of that object.
 */
static struct kfence_freelist kfence_freelist = { .list = LIST_HEAD_INIT(kfence_freelist.list) };
static struct kfence_freelist kfence_recycle = { .list = LIST_HEAD_INIT(kfence_recycle.list) };

struct kfence_alloc_metadata *kfence_metadata;

/* Requres kfence_alloc_lock. */
static noinline void save_stack(int index, bool is_alloc)
{
	unsigned long nr_entries;
	unsigned long *entries =
		is_alloc ? kfence_metadata[index].stack_alloc : kfence_metadata[index].stack_free;

	nr_entries = stack_trace_save(entries, KFENCE_STACK_DEPTH, 1);
	/* TODO(glider): filter_irq_stacks() requires stackdepot. */
	/* nr_entries = filter_irq_stacks(entries, nr_entries); */
	if (is_alloc)
		kfence_metadata[index].nr_alloc = nr_entries;
	else
		kfence_metadata[index].nr_free = nr_entries;
}

noinline void kfence_disable(void)
{
	pr_err("Disabling KFENCE\n");
	WRITE_ONCE(kfence_enabled, false);
}

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

bool kfence_force_4k_pages(unsigned long addr)
{
	unsigned int level;
	pte_t *pte;

	while (addr < (unsigned long)__kfence_pool_end()) {
		pte = lookup_address(addr, &level);
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
	unsigned long addr_end;
	pte_t *pte, new_pte;
	unsigned int level;

	addr_end = addr + PAGE_SIZE;
	pte = lookup_address(addr, &level);
	if (KFENCE_WARN_ON(!pte) || KFENCE_WARN_ON(level != PG_LEVEL_4K))
		return false;
	new_pte =
		__pte(protect ? (pte_val(*pte) & ~_PAGE_PRESENT) : (pte_val(*pte) | _PAGE_PRESENT));
	set_pte(pte, new_pte);
	/* TODO: figure out how to flush TLB properly here. */
	flush_tlb_one_kernel(addr);
	return true;
}

static inline bool kfence_protect(unsigned long addr)
{
	return kfence_change_page_prot(addr, true);
}

static inline bool kfence_unprotect(unsigned long addr)
{
	return kfence_change_page_prot(addr, false);
}

static bool __meminit kfence_allocate_pool(void)
{
	struct page *pages = NULL;
	struct kfence_freelist *objects = NULL;
	unsigned long addr = (unsigned long)__kfence_pool_start;
	int i;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO;

	pages = virt_to_page(addr);
	if (!kfence_force_4k_pages(addr))
		goto error;
	pr_info("allocated pages: 0x%px-0x%px\n", (void *)__kfence_pool_start,
		(void *)__kfence_pool_end());

	/*
	 * Set up non-redzone pages: they must have PG_slab flag and point to
	 * kfence slab cache.
	 */
	for (i = 0; i < (2 << KFENCE_NUM_OBJ_LOG); i++) {
		if (i && !(i % 2)) {
			__SetPageSlab(&pages[i]);
			/*
			 * Do not add KFENCE pages to slab cache partial lists,
			 * they will just mess up the accounting.
			 */
			pages[i].frozen = 1;
		}
	}
	/* Skip the first page: it is reserved. */
	addr += PAGE_SIZE;
	/* Protect the leading redzone. */
	if (!kfence_protect(addr))
		goto error;
	addr += PAGE_SIZE;
	objects = (struct kfence_freelist *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct kfence_freelist), gfp_flags);
	if (!objects)
		goto error;
	for (i = 0; i < KFENCE_NUM_OBJ; i++) {
		objects[i].obj = (void *)addr;
		list_add_tail(&(objects[i].list), &kfence_freelist.list);
		/* Protect the right redzone. */
		if (!kfence_protect(addr + PAGE_SIZE))
			goto error;
		addr += 2 * PAGE_SIZE;
	}

	/* Set up metadata nodes. */
	kfence_metadata = (struct kfence_alloc_metadata *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct kfence_alloc_metadata), gfp_flags);
	if (!kfence_metadata)
		goto error;
	return true;
error:
	kfree(objects);
	kfree(kfence_metadata);
	return false;
}

/* Does not require kfence_alloc_lock. */
static inline int kfence_addr_to_index(unsigned long addr)
{
	if (!is_kfence_addr((void *)addr))
		return -1;

	return ((addr - (unsigned long)__kfence_pool_start) / PAGE_SIZE / 2) - 1;
}

size_t kfence_ksize(const void *addr)
{
	int index = kfence_addr_to_index((unsigned long)addr);

	if (index == -1)
		return 0;
	return abs(READ_ONCE(kfence_metadata[index].size));
}

/* Write canary byte to @addr. */
static void set_canary_byte(u8 *addr)
{
	*addr = KFENCE_CANARY_PATTERN(addr);
}

/* Check canary byte at @addr. */
static void check_canary_byte(u8 *addr)
{
	if (*addr != KFENCE_CANARY_PATTERN(addr)) {
		int obj_index = kfence_addr_to_index((unsigned long)addr);
		kfence_report_error((unsigned long)addr, &kfence_metadata[obj_index],
				    KFENCE_ERROR_CORRUPTION);
	}
}

/*
 * When performing bulk deallocations the freelist pointer in our object may be
 * overwritten with a NULL. If this happened, reinstate the pattern bytes so
 * that we don't report a false memory corruption.
 */
static void check_cache_freelist_ptr(int index)
{
#if defined(CONFIG_SLUB)
	struct kfence_alloc_metadata *meta = &kfence_metadata[index];
	unsigned long freeptr;
	int i;

	if (!meta->cache)
		return;

	freeptr = meta->addr + meta->cache->offset;

	/*
	 * kfree_bulk() might have set @freeptr to zero. If so, restore the
	 * pattern. A different @freeptr value will be detected by
	 * check_canary_byte() later on.
	 */
	if (*(void **)freeptr)
		return;

	for (i = 0; i < sizeof(void *); i++)
		set_canary_byte((u8 *)freeptr + i);
#endif
}

static void for_each_canary(int index, void (*fn)(u8 *))
{
	unsigned long start = kfence_metadata[index].addr;
	int size = abs(kfence_metadata[index].size);
	unsigned long addr;

	for (addr = ALIGN_DOWN(start, PAGE_SIZE); addr < start; addr++)
		fn((char *)addr);
	for (addr = start + size; addr < ALIGN(start, PAGE_SIZE); addr++)
		fn((char *)addr);
}

/* The static key to set up a KFENCE allocation. */
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);

/* Gates the allocation, ensuring only one succeeds in a given period. */
static atomic_t allocation_gate = ATOMIC_INIT(1);
/* Wait queue to wake up heartbeat timer task. */
static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);

static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
{
	unsigned long flags;
	void *obj = NULL, *ret;
	struct kfence_freelist *item;
	int index = -1;
	struct page *page;
	/*
	 * Note: for allocations made before RNG initialization prandom_u32_max() will always return
	 * zero. We still benefit from enabling KFENCE as early as possible, even when the RNG is
	 * not yet available, as this will allow KFENCE to detect bugs due to earlier allocations.
	 * The only downside is that the out-of-bounds accesses detected are deterministic for such
	 * allocations.
	 */
	bool right = prandom_u32_max(2);

	if (KFENCE_WARN_ON(!size || (size > PAGE_SIZE)))
		return NULL;
	spin_lock_irqsave(&kfence_alloc_lock, flags);

	if (!list_empty(&kfence_freelist.list)) {
		item = list_entry(kfence_freelist.list.next, struct kfence_freelist, list);
		obj = item->obj;
		list_del(&(item->list));
		list_add(&(item->list), &kfence_recycle.list);
	}

	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	if (obj) {
		if (right)
			ret = (void *)((char *)obj + PAGE_SIZE - size);
		else
			ret = obj;
		ret = (void *)ALIGN_DOWN((unsigned long)ret, cache->align);
		index = kfence_addr_to_index((unsigned long)obj);
		if (kfence_metadata[index].state == KFENCE_OBJECT_FREED)
			kfence_unprotect((unsigned long)obj);

		kfence_metadata[index].addr = (unsigned long)ret;
		if (gfp & __GFP_ZERO)
			memset(ret, 0, size);
		save_stack(index, true);
		kfence_metadata[index].cache = cache;
		WRITE_ONCE(kfence_metadata[index].size, right ? -size : size);
		kfence_metadata[index].state = KFENCE_OBJECT_ALLOCATED;
		page = virt_to_page(obj);
		page->slab_cache = cache;
		for_each_canary(index, set_canary_byte);
		if (cache->ctor)
			cache->ctor(ret);
	} else {
		ret = NULL;
	}

	pr_debug("allocated object kfence-#%d\n", index);
	return ret;
}

void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	void *ret;

	/*
	 * allocation_gate only needs to become non-zero, so it doesn't make
	 * sense to continue writing to it and pay the associated contention
	 * cost, in case we have a large number of concurrent allocations.
	 */
	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) > 1)
		return NULL;
	wake_up(&allocation_wait);

	if (!kfence_is_enabled())
		return NULL;

	// TODO(elver): Remove one of the comparisons, which is redundant.
	if ((size > PAGE_SIZE) || (s->size > PAGE_SIZE))
		return NULL;
	if (s->flags & SLAB_TYPESAFE_BY_RCU)
		return NULL;

	ret = kfence_guarded_alloc(s, size, flags);

	return ret;
}

bool __kfence_free(void *addr)
{
	unsigned long flags;
	unsigned long aligned_addr = ALIGN_DOWN((unsigned long)addr, PAGE_SIZE);
	struct kfence_freelist *item;
	int index;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	item = list_entry(kfence_recycle.list.next, struct kfence_freelist, list);
	item->obj = (void *)aligned_addr;
	list_del(&(item->list));
	list_add_tail(&(item->list), &kfence_freelist.list);
	index = kfence_addr_to_index((unsigned long)addr);
	check_cache_freelist_ptr(index);
	for_each_canary(index, check_canary_byte);
	save_stack(index, false);
	kfence_metadata[index].state = KFENCE_OBJECT_FREED;
	kfence_protect(aligned_addr);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	pr_debug("freed object kfence-#%d\n", index);
	/* TODO(glider): detect double-frees. */
	return true;
}

bool kfence_handle_page_fault(unsigned long addr)
{
	int page_index, obj_index, report_index = -1, dist = 0, ndist;
	unsigned long flags;

	if (!is_kfence_addr((void *)addr))
		return false;

	if (!kfence_is_enabled()) {
		/* KFENCE has been disabled, unprotect the page and go on. */
		return kfence_unprotect(addr);
	}

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	page_index = (addr - (unsigned long)__kfence_pool_start) / PAGE_SIZE;
	if (page_index % 2) {
		/* This is a redzone, report a buffer overflow. */
		if (page_index > 1) {
			obj_index = kfence_addr_to_index(addr - PAGE_SIZE);
			if (kfence_metadata[obj_index].state == KFENCE_OBJECT_ALLOCATED) {
				report_index = obj_index;
				dist = addr - (kfence_metadata[obj_index].addr +
					       abs(READ_ONCE(kfence_metadata[obj_index].size)));
			}
		}
		if (page_index < (KFENCE_NUM_OBJ + 1) * 2) {
			obj_index = kfence_addr_to_index(addr + PAGE_SIZE);
			if (kfence_metadata[obj_index].state == KFENCE_OBJECT_ALLOCATED) {
				ndist = kfence_metadata[obj_index].addr - addr;
				if ((report_index == -1) || (dist > ndist))
					report_index = obj_index;
			}
		}
		if (report_index != -1) {
			kfence_report_error(addr, &kfence_metadata[report_index], KFENCE_ERROR_OOB);
			spin_unlock_irqrestore(&kfence_alloc_lock, flags);
		} else {
			spin_unlock_irqrestore(&kfence_alloc_lock, flags);
			pr_err("wild redzone access, possible out-of-bounds access!\n");
			/* Let the kernel deal with it. */
			return false;
		}
	} else {
		report_index = kfence_addr_to_index(addr);
		kfence_report_error(addr, &kfence_metadata[report_index], KFENCE_ERROR_UAF);
		spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	}

	/*
	 * Let the kernel proceed.
	 * TODO: either disable KFENCE here, or reinstate the protection later.
	 */
	return kfence_unprotect(addr);
}

bool kfence_discard_slab(struct kmem_cache *s, struct page *page)
{
	if (!is_kfence_addr(page_address(page)))
		return false;
	/* Nothing here for now, but maybe we need to free the objects. */
	return true;
}

bool kfence_shutdown_cache(struct kmem_cache *s)
{
	unsigned long flags;
	int i;
	struct kfence_alloc_metadata *meta;
	bool ret = false;

	spin_lock_irqsave(&kfence_alloc_lock, flags);

	for (i = 0; i < KFENCE_NUM_OBJ; i++) {
		meta = &kfence_metadata[i];
		if ((meta->cache == s) && (meta->state == KFENCE_OBJECT_ALLOCATED))
			goto leave;
	}

	for (i = 0; i < KFENCE_NUM_OBJ; i++) {
		meta = &kfence_metadata[i];
		if ((meta->cache == s) && (meta->state == KFENCE_OBJECT_FREED))
			meta->cache = NULL;
	}
	ret = true;

leave:
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	return ret;
}

/*
 * debugfs seq_file operations for /sys/kernel/debug/kfence/objects.
 * obj_start() and obj_next() return the object index + 1, because NULL is used
 * to stop iteration.
 */
static void *obj_start(struct seq_file *seq, loff_t *pos)
{
	if (*pos < KFENCE_NUM_OBJ)
		return (void *)(*pos + 1);
	return NULL;
}

static void obj_stop(struct seq_file *seq, void *v)
{
}

static void *obj_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	if (*pos < KFENCE_NUM_OBJ)
		return (void *)(*pos + 1);
	return NULL;
}

static int obj_show(struct seq_file *seq, void *v)
{
	long index = (long)v - 1;
	unsigned long flags;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	kfence_dump_object(seq, &kfence_metadata[index]);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	seq_printf(seq, "---------------------------------\n");

	return 0;
}

static const struct seq_operations obj_seqops = {
	.start = obj_start,
	.next = obj_next,
	.stop = obj_stop,
	.show = obj_show,
};

static int kfence_debugfs_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &obj_seqops);
}

static const struct file_operations obj_fops = {
	.open = kfence_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
};

/*
 * Current debugfs structure:
 *  /sys/kernel/debug/kfence/ - KFENCE directory;
 *    objects - file listing all objects.
 */
void __init kfence_create_debugfs(void)
{
	struct dentry *kfence_dir;
	kfence_dir = debugfs_create_dir("kfence", NULL);
	debugfs_create_file_unsafe("objects", 0400, kfence_dir, NULL, &obj_fops);
}

device_initcall(kfence_create_debugfs);

/*
 * Set up delayed work, which will enable and disable the static key. We need to
 * use a work queue (rather than a simple timer), since enabling and disabling a
 * static key cannot be done from an interrupt.
 */
static struct delayed_work kfence_timer;
static void kfence_heartbeat(struct work_struct *work)
{
	if (!kfence_is_enabled())
		return;

	/* Enable static key, and await allocation to happen. */
	atomic_set(&allocation_gate, 0);
	static_branch_enable(&kfence_allocation_key);
	wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);

	/* Disable static key and reset timer. */
	static_branch_disable(&kfence_allocation_key);
	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_rate));
}
static DECLARE_DELAYED_WORK(kfence_timer, kfence_heartbeat);

void __init kfence_init(void)
{
	if (!kfence_sample_rate)
		/* The tool is disabled. */
		return;

	if (!kfence_allocate_pool()) {
		pr_err("%s failed\n", __func__);
		return;
	}

	schedule_delayed_work(&kfence_timer, 0);
	WRITE_ONCE(kfence_enabled, true);
	pr_info("initialized\n");
}
