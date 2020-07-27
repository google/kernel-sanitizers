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

#include <asm/kfence.h>

#include "kfence.h"

/* Disables KFENCE on the first warning assuming an irrecoverable error. */
// clang-format off
#define KFENCE_WARN_ON(cond)                                                   \
	({                                                                     \
		const bool __cond = WARN_ON(cond);                             \
		if (unlikely(__cond))                                          \
			WRITE_ONCE(kfence_enabled, false);                     \
		__cond;                                                        \
	})
// clang-format on

static unsigned long kfence_sample_rate __read_mostly = CONFIG_KFENCE_SAMPLE_RATE;

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
module_param_named(sample_rate, kfence_sample_rate, ulong, 0400);

static bool kfence_enabled __read_mostly;

/* TODO: explain alignment. */
char __kfence_pool[KFENCE_POOL_SIZE] __aligned(2 << 21);
EXPORT_SYMBOL(__kfence_pool);

/* Protects kfence_freelist, kfence_recycle, kfence_metadata */
// TODO(elver): We need to find a way to make KFENCE lockless, as it seems to be
// unhappy with lockdep.
static DEFINE_SPINLOCK(kfence_alloc_lock);

/*
 * Per-object metadata, with one-to-one mapping of object metadata to
 * backing pages (in __kfence_pool).
 */
static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];

/* Freelist with available objects. */
static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);

/* The static key to set up a KFENCE allocation. */
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);

/* Gates the allocation, ensuring only one succeeds in a given period. */
static atomic_t allocation_gate = ATOMIC_INIT(1);
/* Wait queue to wake up heartbeat timer task. */
static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);

/*
 * TODO(elver): With the move of arch-specific code to asm, kfence core.c got a
 * lot simpler. Maybe we can move report.c code back here and remove the kfence/
 * dir? Although, currently the test wants something from kfence.h (but it can
 * be made standalone), and I'd hate to have more than 2 new files in mm/. If we
 * do this, we'd need to end up only with mm/{kfence.c,kfence-test.c}.
 */

static inline bool kfence_protect(unsigned long addr)
{
	return !KFENCE_WARN_ON(!kfence_change_page_prot(ALIGN_DOWN(addr, PAGE_SIZE), true));
}

static inline bool kfence_unprotect(unsigned long addr)
{
	return !KFENCE_WARN_ON(!kfence_change_page_prot(ALIGN_DOWN(addr, PAGE_SIZE), false));
}

/* Does not require kfence_alloc_lock. */
static inline int kfence_addr_to_index(unsigned long addr)
{
	if (!is_kfence_addr((void *)addr))
		return -1;

	return ((addr - (unsigned long)__kfence_pool) / PAGE_SIZE / 2) - 1;
}

size_t kfence_ksize(const void *addr)
{
	const int index = kfence_addr_to_index((unsigned long)addr);

	return index == -1 ? 0 : abs(READ_ONCE(kfence_metadata[index].size));
}

/* Requres kfence_alloc_lock. */
static noinline void metadata_update_state(struct kfence_metadata *meta,
					   enum kfence_object_state next)
{
	unsigned long *entries = next == KFENCE_OBJECT_FREED ? meta->stack_free : meta->stack_alloc;
	unsigned long nr_entries = stack_trace_save(entries, KFENCE_STACK_DEPTH, 1);

	/* TODO(glider): filter_irq_stacks() requires stackdepot. Needed? */
	/* nr_entries = filter_irq_stacks(entries, nr_entries); */

	if (next == KFENCE_OBJECT_FREED)
		meta->nr_free = nr_entries;
	else
		meta->nr_alloc = nr_entries;

	meta->state = next;
}

/* Write canary byte to @addr. */
static bool set_canary_byte(u8 *addr)
{
	*addr = KFENCE_CANARY_PATTERN(addr);
	return true;
}

/* Check canary byte at @addr. */
static bool check_canary_byte(u8 *addr)
{
	int obj_index;

	if (*addr == KFENCE_CANARY_PATTERN(addr))
		return true;

	obj_index = kfence_addr_to_index((unsigned long)addr);
	kfence_report_error((unsigned long)addr, &kfence_metadata[obj_index],
			    KFENCE_ERROR_CORRUPTION);
	return false;
}

static void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
{
	const int size = abs(meta->size);
	unsigned long addr;

	for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
		if (!fn((u8 *)addr))
			break;
	}

	for (addr = meta->addr + size; addr < ALIGN(meta->addr, PAGE_SIZE); addr++) {
		if (!fn((u8 *)addr))
			break;
	}
}

static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
{
	/*
	 * Note: for allocations made before RNG initialization, will always
	 * return zero. We still benefit from enabling KFENCE as early as
	 * possible, even when the RNG is not yet available, as this will allow
	 * KFENCE to detect bugs due to earlier allocations. The only downside
	 * is that the out-of-bounds accesses detected are deterministic for
	 * such allocations.
	 */
	const bool right = prandom_u32_max(2);
	unsigned long flags;
	struct kfence_metadata *meta;
	void *ret = NULL;

	// TODO(elver): Why do we need this WARN?
	if (KFENCE_WARN_ON(!size || (size > PAGE_SIZE)))
		return NULL;

	if (list_empty(&kfence_freelist))
		return NULL; /* All objects in use. */

	/* Obtain a free object. */
	spin_lock_irqsave(&kfence_alloc_lock, flags);
	meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
	list_del_init(&meta->list);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);

	meta->addr = ALIGN_DOWN(meta->addr, PAGE_SIZE);
	/* Unprotect if we're reusing this page. */
	if (meta->state == KFENCE_OBJECT_FREED)
		kfence_unprotect(meta->addr);

	/* Calculate address for this allocation. */
	if (right)
		meta->addr += PAGE_SIZE - size;
	meta->addr = ALIGN_DOWN(meta->addr, cache->align);

	/* Update remaining metadata. */
	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
	meta->cache = cache;
	meta->size = right ? -size : size;
	for_each_canary(meta, set_canary_byte);
	virt_to_page(meta->addr)->slab_cache = cache;

	/* Initialization. */
	ret = (void *)meta->addr;
	if (gfp & __GFP_ZERO)
		memset(ret, 0, size);
	if (cache->ctor)
		cache->ctor(ret);

	pr_debug("allocated object kfence-#%d\n", kfence_addr_to_index(meta->addr));

	if (IS_ENABLED(CONFIG_KFENCE_FAULT_INJECTION) && !prandom_u32_max(10))
		kfence_protect(meta->addr);

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

	if (!READ_ONCE(kfence_enabled))
		return NULL;

	// TODO(elver): Remove one of the comparisons, which is redundant.
	if ((size > PAGE_SIZE) || (s->size > PAGE_SIZE))
		return NULL;

	/*
	 * TODO(elver): Handle this. We can easily handle it if we defer free
	 * with call_rcu in __kfence_free.
	 */
	if (s->flags & SLAB_TYPESAFE_BY_RCU)
		return NULL;

	ret = kfence_guarded_alloc(s, size, flags);

	return ret;
}

bool __kfence_free(void *addr)
{
	unsigned long flags;
	struct kfence_metadata *meta;

	if (IS_ENABLED(CONFIG_KFENCE_FAULT_INJECTION))
		kfence_unprotect((unsigned long)addr); /* To check canary bytes. */

	spin_lock_irqsave(&kfence_alloc_lock, flags);

	/* Find the matching metadata. */
	meta = &kfence_metadata[kfence_addr_to_index((unsigned long)addr)];
	KFENCE_WARN_ON(!list_empty(&meta->list)); /* API misuse? */

	/* Restore page protection if there was an OOB access. */
	if (meta->unprotected_page) {
		kfence_protect(meta->unprotected_page);
		meta->unprotected_page = 0;
	}

	/* Check canary bytes for memory corruption. */
	for_each_canary(meta, check_canary_byte);

	/* Mark the object as freed. */
	metadata_update_state(meta, KFENCE_OBJECT_FREED);
	kfence_protect((unsigned long)addr);

	/* Add it to the tail of the freelist. */
	list_add_tail(&meta->list, &kfence_freelist);

	spin_unlock_irqrestore(&kfence_alloc_lock, flags);

	pr_debug("freed object kfence-#%d\n", kfence_addr_to_index((unsigned long)addr));
	/* TODO(glider): detect double-frees. */
	return true;
}

bool kfence_handle_page_fault(unsigned long addr)
{
	int page_index, obj_index, report_index = -1, dist = 0, ndist;
	unsigned long flags;

	if (!is_kfence_addr((void *)addr))
		return false;

	if (!READ_ONCE(kfence_enabled)) {
		/* KFENCE has been disabled, unprotect the page and go on. */
		return kfence_unprotect(addr);
	}

	/*
	 * If there is a KFENCE report somewhere inside lockdep, or one of the
	 * libraries used by it, we need to avoid recursing back into lockdep.
	 */
	// TODO(elver): This is probably also a problem for allocations/frees.
	lockdep_off();
	spin_lock_irqsave(&kfence_alloc_lock, flags);

	page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
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

		if (page_index < (CONFIG_KFENCE_NUM_OBJECTS + 1) * 2) {
			obj_index = kfence_addr_to_index(addr + PAGE_SIZE);
			if (kfence_metadata[obj_index].state == KFENCE_OBJECT_ALLOCATED) {
				ndist = kfence_metadata[obj_index].addr - addr;
				if ((report_index == -1) || (dist > ndist))
					report_index = obj_index;
			}
		}

		if (report_index == -1) {
			spin_unlock_irqrestore(&kfence_alloc_lock, flags);
			pr_err("wild redzone access, possible out-of-bounds access!\n");
			/* Let the kernel deal with it. */
			return false;
		}

		kfence_report_error(addr, &kfence_metadata[report_index], KFENCE_ERROR_OOB);
		kfence_metadata[report_index].unprotected_page = addr;
	} else {
		report_index = kfence_addr_to_index(addr);
		KFENCE_WARN_ON(!IS_ENABLED(CONFIG_KFENCE_FAULT_INJECTION) &&
			       kfence_metadata[report_index].state != KFENCE_OBJECT_FREED);
		kfence_report_error(addr, &kfence_metadata[report_index], KFENCE_ERROR_UAF);
	}

	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	lockdep_on();
	/* Unprotect and let access proceed. */
	return kfence_unprotect(addr);
}

bool kfence_discard_slab(struct kmem_cache *s, struct page *page)
{
	if (!is_kfence_addr(page_address(page)))
		return false;
	/* TODO: Nothing here for now, but maybe we need to free the objects. */
	return true;
}

bool kfence_shutdown_cache(struct kmem_cache *s)
{
	unsigned long flags;
	int i;
	struct kfence_metadata *meta;
	bool ret = false;

	spin_lock_irqsave(&kfence_alloc_lock, flags);

	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
		meta = &kfence_metadata[i];
		if ((meta->cache == s) && (meta->state == KFENCE_OBJECT_ALLOCATED))
			goto leave;
	}

	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
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
	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
		return (void *)(*pos + 1);
	return NULL;
}

static void obj_stop(struct seq_file *seq, void *v)
{
}

static void *obj_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
		return (void *)(*pos + 1);
	return NULL;
}

static int obj_show(struct seq_file *seq, void *v)
{
	long index = (long)v - 1;
	unsigned long flags;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	kfence_print_object(seq, &kfence_metadata[index]);
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
	if (!READ_ONCE(kfence_enabled))
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

static bool __meminit kfence_initialize_pool(void)
{
	unsigned long addr = (unsigned long)__kfence_pool;
	struct page *pages = virt_to_page(addr);
	int i;

	if (!arch_kfence_initialize_pool())
		return false;

	pr_info("memory range: 0x%px-0x%px\n", (void *)__kfence_pool,
		(void *)(__kfence_pool + KFENCE_POOL_SIZE));

	/*
	 * Set up non-redzone pages: they must have PG_slab flag and point to
	 * kfence slab cache.
	 */
	// TODO(elver): Why?
	for (i = 0; i < sizeof(__kfence_pool) / PAGE_SIZE; i++) {
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
	// TODO(elver): Why is it reserved?
	addr += PAGE_SIZE;

	/* Protect the leading (right) redzone. */
	if (!kfence_protect(addr))
		return false;

	addr += PAGE_SIZE;

	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
		struct kfence_metadata *meta = &kfence_metadata[i];

		meta->addr = addr; /* ALIGN_DOWN(meta->addr, PAGE_SIZE) must be constant. */
		if (KFENCE_WARN_ON(ALIGN_DOWN(addr, PAGE_SIZE) != addr))
			return false; /* Something went terribly wrong. */

		list_add_tail(&meta->list, &kfence_freelist);

		/* Protect the right redzone. */
		if (!kfence_protect(addr + PAGE_SIZE))
			return false;

		addr += 2 * PAGE_SIZE;
	}

	return true;
}

void __init kfence_init(void)
{
	/* Setting kfence_sample_rate to 0 on boot disables KFENCE. */
	if (!kfence_sample_rate)
		return;

	if (!kfence_initialize_pool()) {
		pr_err("%s failed\n", __func__);
		return;
	}

	schedule_delayed_work(&kfence_timer, 0);
	WRITE_ONCE(kfence_enabled, true);
	pr_info("initialized\n");
}
