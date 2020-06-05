// SPDX-License-Identifier: GPL-2.0

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <linux/list.h>
#include <linux/debugfs.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock_types.h>
#include <linux/stackdepot.h>
#include <linux/timer.h>

#include "kfence_core.h"
#include "../slab.h"

/* Usually on, unless explicitly disabled. */
bool kfence_enabled;

enum kfence_object_state {
	KFENCE_OBJECT_UNUSED,
	KFENCE_OBJECT_ALLOCATED,
	KFENCE_OBJECT_FREED
};

struct kfence_freelist {
	struct list_head list;
	void *obj;
};

struct alloc_metadata {
	depot_stack_handle_t alloc_stack, free_stack;
	struct kmem_cache *cache;
	/* >0: left alignment, <0: right alignment. */
	int size;
	enum kfence_object_state state;
};

/*
 * It's handy (but not strictly required) that 255 objects with redzones occupy
 * exactly 2Mb.
 */
#define KFENCE_NUM_OBJ_LOG 8
#define KFENCE_NUM_OBJ ((1 << KFENCE_NUM_OBJ_LOG) - 1)

static unsigned long kfence_pool_start, kfence_pool_end;

/* Protects kfence_freelist, kfence_recycle, kfence_metadata */
static DEFINE_SPINLOCK(kfence_alloc_lock);

/* Size picked to accommodate the metadata of a single KFENCE object. */
static char kfence_dump_buf[PAGE_SIZE * 2];

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
static struct kfence_freelist kfence_freelist = {
	.list = LIST_HEAD_INIT(kfence_freelist.list)
};
static struct kfence_freelist kfence_recycle = { .list = LIST_HEAD_INIT(
							 kfence_recycle.list) };

static struct alloc_metadata *kfence_metadata;

#define KFENCE_DEFAULT_SAMPLE_RATE 100
#define KFENCE_STACK_DEPTH 64

/* TODO: there's a similar function in KASAN already. */
static inline depot_stack_handle_t save_stack(gfp_t flags)
{
	unsigned long entries[KFENCE_STACK_DEPTH];
	unsigned long nr_entries;

	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
	/*
	 * TODO: filter_irq_stacks() is in linux-next, uncomment when it reaches
	 * mainline.
	 */
	/*nr_entries = filter_irq_stacks(entries, nr_entries);*/
	return stack_depot_save(entries, nr_entries, flags);
}

noinline void kfence_disable(void)
{
	pr_err("Disabling KFENCE\n");
	WRITE_ONCE(kfence_enabled, false);
}

/* TODO(glider): kernel_physical_mapping_change() is x86-only */
unsigned long kernel_physical_mapping_change(unsigned long start,
					     unsigned long end,
					     unsigned long page_size_mask);

static bool kfence_force_4k_pages(void)
{
	unsigned long addr = kfence_pool_start, addr_end;
	unsigned int level;
	unsigned long psize, pmask;
	pte_t *pte;

	while (addr < kfence_pool_end) {
		pte = lookup_address(addr, &level);
		if (!pte)
			return false;
		if (level != PG_LEVEL_4K) {
			psize = page_level_size(level);
			pmask = page_level_mask(level);
			addr_end = ((addr + PAGE_SIZE) & pmask) + psize;
			kernel_physical_mapping_change(__pa(addr & pmask),
						       __pa(addr_end),
						       1 << PG_LEVEL_4K);
			addr = addr_end;
		} else {
			addr += PAGE_SIZE;
		}
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
	new_pte = __pte(protect ? (pte_val(*pte) & ~_PAGE_PRESENT) :
				  (pte_val(*pte) | _PAGE_PRESENT));
	set_pte(pte, new_pte);
	/* TODO: figure out how to flush TLB properly here. */
	__flush_tlb_one_kernel(addr);
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

bool __meminit kfence_allocate_pool(void)
{
	struct page *pages = NULL;
	struct kfence_freelist *objects = NULL;
	unsigned long addr;
	int i;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO;

	pages = alloc_pages(GFP_KERNEL, KFENCE_NUM_OBJ_LOG + 1);
	if (!pages)
		goto error;
	kfence_pool_start = (unsigned long)page_address(pages);
	kfence_pool_end =
		kfence_pool_start + (KFENCE_NUM_OBJ + 1) * 2 * PAGE_SIZE;
	if (!kfence_force_4k_pages())
		goto error;
	pr_info("kfence allocated pages: %px--%px\n", (void *)kfence_pool_start,
		(void *)kfence_pool_end);
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
	addr = kfence_pool_start;
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
	kfence_metadata = (struct alloc_metadata *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct alloc_metadata), gfp_flags);
	return true;
error:
	if (pages)
		__free_pages(pages, KFENCE_NUM_OBJ_LOG + 1);
	kfree(objects);
	return false;
}

bool is_kfence_addr(void *addr)
{
	unsigned long uaddr = (unsigned long)addr;
	return ((uaddr >= kfence_pool_start) && (uaddr < kfence_pool_end));
}
EXPORT_SYMBOL(is_kfence_addr);

/* Does not require kfence_alloc_lock. */
static inline int kfence_addr_to_index(unsigned long addr)
{
	if (!is_kfence_addr((void *)addr))
		return -1;

	return ((addr - kfence_pool_start) / PAGE_SIZE / 2) - 1;
}

/* Does not require kfence_alloc_lock. */
static inline unsigned long kfence_obj_to_addr(struct alloc_metadata *obj,
					       int index)
{
	int size = obj->size;
	unsigned long ret;

	if ((index < 0) || (index >= KFENCE_NUM_OBJ))
		return 0;
	ret = kfence_pool_start + PAGE_SIZE * 2 * (index + 1);
	if (size > 0)
		return ret;
	else
		return ret + PAGE_SIZE + size;
}

/* Requires kfence_alloc_lock. */
static inline unsigned long kfence_index_to_addr(int index)
{
	struct alloc_metadata *obj = &kfence_metadata[index];

	return kfence_obj_to_addr(obj, index);
}

void *kfence_guarded_alloc(struct kmem_cache *cache, size_t override_size,
			   gfp_t gfp)
{
	unsigned long flags;
	void *obj = NULL, *ret;
	struct kfence_freelist *item;
	int index = -1;
	bool right = prandom_u32_max(2);
	size_t size = override_size ? override_size : cache->size;
	struct page *page;

	if (KFENCE_WARN_ON(size > PAGE_SIZE))
		return NULL;
	spin_lock_irqsave(&kfence_alloc_lock, flags);

	if (!list_empty(&kfence_freelist.list)) {
		item = list_entry(kfence_freelist.list.next,
				  struct kfence_freelist, list);
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
		index = kfence_addr_to_index((unsigned long)obj);
		if (kfence_metadata[index].state == KFENCE_OBJECT_FREED)
			kfence_unprotect((unsigned long)obj);
		/*
		 * Reclaiming memory when storing stacks may result in
		 * unnecessary locking.
		 */
		kfence_metadata[index].alloc_stack =
			save_stack(gfp & ~__GFP_RECLAIM);
		kfence_metadata[index].cache = cache;
		kfence_metadata[index].size = right ? -size : size;
		kfence_metadata[index].state = KFENCE_OBJECT_ALLOCATED;
		page = virt_to_page(obj);
		page->slab_cache = cache;
	} else {
		ret = NULL;
	}
	pr_debug("kfence_guarded_alloc(%ld) returns %px\n", size, ret);
	pr_debug("allocated object #%d\n", index);
	return ret;
}

void kfence_guarded_free(void *addr)
{
	unsigned long flags;
	unsigned long aligned_addr = ALIGN_DOWN((unsigned long)addr, PAGE_SIZE);
	struct kfence_freelist *item;
	int index;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	item = list_entry(kfence_recycle.list.next, struct kfence_freelist,
			  list);
	item->obj = (void *)aligned_addr;
	list_del(&(item->list));
	list_add_tail(&(item->list), &kfence_freelist.list);
	index = kfence_addr_to_index((unsigned long)addr);
	/* GFP_ATOMIC to avoid reclaiming memory. */
	kfence_metadata[index].free_stack = save_stack(GFP_ATOMIC);
	kfence_metadata[index].state = KFENCE_OBJECT_FREED;
	kfence_protect(aligned_addr);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	pr_debug("freed object #%d\n", index);
}

bool kfence_free(struct kmem_cache *s, struct page *page, void *head,
		 void *tail, int cnt, unsigned long addr)
{
	void *aligned_head = (void *)ALIGN_DOWN((unsigned long)head, PAGE_SIZE);

	if (!is_kfence_addr(head))
		return false;
	if (KFENCE_WARN_ON(head != tail))
		return false;
	pr_debug("kfence_free(%px)\n", head);
	if (KFENCE_WARN_ON(aligned_head != page_address(page)))
		return false;
	kfence_guarded_free(head);
	return true;
}

static int kfence_dump_stack(char *buf, size_t buf_size,
			     struct alloc_metadata *obj, bool is_alloc)
{
	unsigned long *entries;
	unsigned long nr_entries;
	depot_stack_handle_t handle;
	int len = 0;

	if (is_alloc)
		handle = obj->alloc_stack;
	else
		handle = obj->free_stack;
	if (handle) {
		nr_entries = stack_depot_fetch(handle, &entries);
		len += stack_trace_snprint(buf + len, buf_size - len, entries,
					   nr_entries, 0);
	} else {
		len += scnprintf(buf + len, buf_size - len, "  no %s stack.\n",
				 is_alloc ? "allocation" : "deallocation");
	}
	return len;
}

static int kfence_dump_object(char *buf, size_t buf_size, int obj_index,
			      struct alloc_metadata *obj)
{
	int size = abs(obj->size);
	unsigned long start = kfence_obj_to_addr(obj, obj_index);
	struct kmem_cache *cache;
	int len = 0;

	len += scnprintf(buf + len, buf_size - len,
			 "Object #%d: starts at %px, size=%d\n", obj_index,
			 (void *)start, size);
	len += scnprintf(buf + len, buf_size - len, "allocated at:\n");
	len += kfence_dump_stack(buf + len, buf_size - len, obj, true);
	if (kfence_metadata[obj_index].state == KFENCE_OBJECT_FREED) {
		len += scnprintf(buf + len, buf_size - len, "freed at:\n");
		len += kfence_dump_stack(buf + len, buf_size - len, obj, false);
	}
	cache = kfence_metadata[obj_index].cache;
	if (cache && cache->name)
		len += scnprintf(buf + len, buf_size - len,
				 "Object #%d belongs to cache %s\n", obj_index,
				 cache->name);
	return len;
}

static void kfence_print_object(int obj_index, struct alloc_metadata *obj)
{
	kfence_dump_object(kfence_dump_buf, sizeof(kfence_dump_buf), obj_index,
			   obj);
	pr_err("%s", kfence_dump_buf);
}

static inline void kfence_report_oob(unsigned long address, int obj_index,
				     struct alloc_metadata *object)
{
	bool is_left = address < kfence_obj_to_addr(object, obj_index);

	pr_err("==================================================================\n");
	pr_err("BUG: KFENCE: slab-out-of-bounds at address %px to the %s of object #%d\n",
	       (void *)address, is_left ? "left" : "right", obj_index);
	dump_stack();
	kfence_print_object(obj_index, object);
	pr_err("==================================================================\n");
}

static inline void kfence_report_uaf(unsigned long address, int obj_index,
				     struct alloc_metadata *object)
{
	pr_err("==================================================================\n");
	pr_err("BUG: KFENCE: use-after-free at address %px on object #%d\n",
	       (void *)address, obj_index);
	dump_stack();
	kfence_print_object(obj_index, object);
	pr_err("==================================================================\n");
}

bool kfence_handle_page_fault(unsigned long addr)
{
	int page_index, obj_index, report_index = -1, dist = 0, ndist;
	unsigned long flags;
	struct alloc_metadata object = {};

	if (!is_kfence_addr((void *)addr))
		return false;

	if (!READ_ONCE(kfence_enabled)) {
		/* KFENCE has been disabled, unprotect the page and go on. */
		return kfence_unprotect(addr);
	}

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	page_index = (addr - kfence_pool_start) / PAGE_SIZE;
	if (page_index % 2) {
		/* This is a redzone, report a buffer overflow. */
		if (page_index > 1) {
			obj_index = kfence_addr_to_index(addr - PAGE_SIZE);
			if (kfence_metadata[obj_index].state ==
			    KFENCE_OBJECT_ALLOCATED) {
				report_index = obj_index;
				dist = addr -
				       (kfence_index_to_addr(obj_index) +
					abs(kfence_metadata[obj_index].size));
			}
		}
		if (page_index < (KFENCE_NUM_OBJ + 1) * 2) {
			obj_index = kfence_addr_to_index(addr + PAGE_SIZE);
			if (kfence_metadata[obj_index].state ==
			    KFENCE_OBJECT_ALLOCATED) {
				ndist = kfence_index_to_addr(obj_index) - addr;
				if ((report_index == -1) || (dist > ndist))
					report_index = obj_index;
			}
		}
		if (report_index != -1) {
			object = kfence_metadata[report_index];
			spin_unlock_irqrestore(&kfence_alloc_lock, flags);
			kfence_report_oob(addr, report_index, &object);
		} else {
			spin_unlock_irqrestore(&kfence_alloc_lock, flags);
			pr_err("BUG: KFENCE: wild redzone access.\n");
			/* Let the kernel deal with it. */
			return false;
		}
	} else {
		report_index = kfence_addr_to_index(addr);
		object = kfence_metadata[report_index];
		spin_unlock_irqrestore(&kfence_alloc_lock, flags);
		kfence_report_uaf(addr, report_index, &object);
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
	kfence_dump_object(kfence_dump_buf, sizeof(kfence_dump_buf), index,
			   &kfence_metadata[index]);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	seq_printf(seq, "%s\n", kfence_dump_buf);
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
	debugfs_create_file_unsafe("objects", 0600, kfence_dir, NULL,
				   &obj_fops);
}

device_initcall(kfence_create_debugfs);

unsigned long kfence_sample_rate = KFENCE_DEFAULT_SAMPLE_RATE;

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
module_param_named(sample_rate, kfence_sample_rate, ulong, 0444);

/*
 * KFENCE depends heavily on random number generation, wait for it to be
 * ready.
 */
static void kfence_enable_after_random(struct random_ready_callback *unused)
{
	kfence_impl_init();
	pr_info("Starting KFENCE\n");
	WRITE_ONCE(kfence_enabled, true);
}

static struct random_ready_callback random_ready = {
	.func = kfence_enable_after_random
};

void __init kfence_init(void)
{
	if (!kfence_sample_rate)
		/* The tool is disabled. */
		return;

	if (kfence_allocate_pool()) {
		if (add_random_ready_callback(&random_ready) == 0)
			return;
	}
	pr_err("kfence_init failed\n");
}
