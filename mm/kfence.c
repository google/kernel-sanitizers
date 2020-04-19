/* KFENCE implementation */

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <linux/mm.h> // required by slub_def.h, should be included there.
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/spinlock_types.h>
#include <linux/stackdepot.h>
#include <linux/timer.h>

/* Usually on, unless explicitly disabled. */
bool kfence_enabled;
static void kfence_heartbeat(struct timer_list *timer);
static DEFINE_TIMER(kfence_timer, kfence_heartbeat);

/*
 * TODO: need to return a freelist back to the cache if it hasn't been used for
 * a while, otherwise we may quickly run out of pages.
 */
#define STORED_FREELISTS 64
struct stored_freelist {
	struct kmem_cache *cache;
	void *freelist;
};

#define KFENCE_MAX_CACHES 256
/*
 * Currently there is less than 100 caches in the running kernel that we need
 * to track. Caches are stored in an array, so that a random cache can be
 * quickly picked.
 */
struct kmem_cache *kfence_registered_caches[KFENCE_MAX_CACHES];
int kfence_num_caches;

enum kfence_object_state {
	KFENCE_OBJECT_UNUSED,
	KFENCE_OBJECT_ALLOCATED,
	KFENCE_OBJECT_FREED
};

struct alloc_metadata {
	depot_stack_handle_t alloc_stack, free_stack;
	struct kmem_cache *cache;
	/* >0: left alignment, <0: right alignment. */
	int size;
	enum kfence_object_state state;
};

/* Protects stolen freelists */
static DEFINE_SPINLOCK(kfence_caches_lock);
struct stored_freelist stored_freelists[STORED_FREELISTS];
int num_stored_freelists;
struct kmem_cache kfence_slab_cache = {
	.name = "kfence_slab_cache",
	.flags = SLAB_KFENCE,

};
EXPORT_SYMBOL(kfence_slab_cache);

/*
 * It's handy (but not strictly required) that 255 objects with redzones occupy
 * exactly 2Mb.
 */
#define KFENCE_NUM_OBJ_LOG 8
#define KFENCE_NUM_OBJ ((1 << KFENCE_NUM_OBJ_LOG) - 1)

unsigned long kfence_pool_start, kfence_pool_end;

/* Protects kfence_freelist, kfence_recycle, kfence_metadata */
static DEFINE_SPINLOCK(kfence_alloc_lock);

struct kfence_freelist_t {
	struct list_head list;
	void *obj;
};
/*
 * kfence_freelist_t is a wrapper around kfence page pointers that allows
 * chaining them.
 * @kfence_freelist is a FIFO queue of non-allocated pages, @kfence_recycle is
 * a stack of unused kfence_freelist_t objects.
 * When allocating a new object in guarded_alloc(), a kfence_freelist_t item is
 * taken from the queue and its @kfence_freelist_t.obj member is used for
 * allocation. The item is put into @kfence_recycle - at this point its contents
 * aren't valid anymore.
 * When freeing an object, it is wrapped into a kfence_freelist_t taken from
 * @kfence_recycle. This kfence_freelist_t item is placed at the end of
 * @kfence_freelist to delay the reuse of that object.
 */
static struct kfence_freelist_t kfence_freelist = {
	.list = LIST_HEAD_INIT(kfence_freelist.list)
};
static struct kfence_freelist_t kfence_recycle = {
	.list = LIST_HEAD_INIT(kfence_recycle.list)
};

static struct alloc_metadata *kfence_metadata;

#define KFENCE_DEFAULT_SAMPLE_RATE 100
#define KFENCE_STACK_DEPTH 64

static unsigned long kfence_sample_rate = KFENCE_DEFAULT_SAMPLE_RATE;

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
module_param_named(sample_rate, kfence_sample_rate, ulong, 0444);

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

static inline void kfence_disable(void)
{
	pr_err("Disabling KFENCE\n");
	WRITE_ONCE(kfence_enabled, false);
}

#define KFENCE_WARN_ON(cond)                                                   \
	({                                                                     \
		bool __cond = WARN_ON(cond);                                   \
		if (unlikely(__cond))                                          \
			kfence_disable();                                      \
		__cond;                                                        \
	})

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

static bool __meminit allocate_pool(void)
{
	struct page *pages = NULL;
	struct kfence_freelist_t *objects = NULL;
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
			pages[i].slab_cache = &kfence_slab_cache;
		}
	}
	addr = kfence_pool_start;
	/* Skip the first page: it is reserved. */
	addr += PAGE_SIZE;
	/* Protect the leading redzone. */
	if (!kfence_protect(addr))
		goto error;
	addr += PAGE_SIZE;
	objects = (struct kfence_freelist_t *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct kfence_freelist_t), gfp_flags);
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

static inline int kfence_addr_to_index(unsigned long addr)
{
	if ((addr < kfence_pool_start) || (addr >= kfence_pool_end))
		return -1;

	return ((addr - kfence_pool_start) / PAGE_SIZE / 2) - 1;
}

static inline unsigned long kfence_index_to_addr(int index)
{
	int size = kfence_metadata[index].size;
	unsigned long ret;

	if ((index < 0) || (index >= KFENCE_NUM_OBJ))
		return 0;
	ret = kfence_pool_start + PAGE_SIZE * 2 * (index + 1);
	if (size > 0)
		return ret;
	else
		return ret + PAGE_SIZE + size;
}

void *guarded_alloc(struct kmem_cache *cache, gfp_t gfp)
{
	unsigned long flags;
	void *obj = NULL, *ret;
	struct kfence_freelist_t *item;
	int index = -1;
	bool right = prandom_u32_max(2);
	size_t size = cache->size;

	if (KFENCE_WARN_ON(size > PAGE_SIZE))
		return NULL;
	spin_lock_irqsave(&kfence_alloc_lock, flags);

	if (!list_empty(&kfence_freelist.list)) {
		item = list_entry(kfence_freelist.list.next,
				  struct kfence_freelist_t, list);
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
	} else {
		ret = NULL;
	}
	pr_debug("guarded_alloc(%ld) returns %px\n", size, ret);
	pr_debug("allocated object #%d\n", index);
	return ret;
}

void guarded_free(void *addr)
{
	unsigned long flags;
	unsigned long aligned_addr = ALIGN_DOWN((unsigned long)addr, PAGE_SIZE);
	struct kfence_freelist_t *item;
	int index;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	item = list_entry(kfence_recycle.list.next, struct kfence_freelist_t,
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

static struct stored_freelist *find_freelist(struct kmem_cache *c)
{
	int i;

	for (i = 0; i < STORED_FREELISTS; i++) {
		if (stored_freelists[i].cache == c)
			return &stored_freelists[i];
	}
	return NULL;
}

static int find_cache(struct kmem_cache *c)
{
	int i;

	for (i = 0; i < KFENCE_MAX_CACHES; i++) {
		if (kfence_registered_caches[i] == c)
			return i;
	}
	return -1;
}

void *kfence_alloc_and_fix_freelist(struct kmem_cache *s, gfp_t gfp)
{
	unsigned long flags;
	struct kmem_cache_cpu *c = raw_cpu_ptr(s->cpu_slab);
	struct stored_freelist *fl;
	void *ret = NULL;
	void *freelist;

	if (!READ_ONCE(kfence_enabled))
		return NULL;
	spin_lock_irqsave(&kfence_caches_lock, flags);
	fl = find_freelist(s);
	if (fl == NULL)
		goto leave;
	freelist = fl->freelist;
	ret = guarded_alloc(s, gfp);
	c->freelist = freelist;
	fl->cache = NULL;
	num_stored_freelists--;
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
	pr_debug("kfence_alloc_and_fix_freelist returns %px\n", ret);
	return ret;
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
	return NULL;
}

bool kfence_free(struct kmem_cache *s, struct page *page, void *head,
		 void *tail, int cnt, unsigned long addr)
{
	void *aligned_head = (void *)ALIGN_DOWN((unsigned long)head, PAGE_SIZE);

	if (s != &kfence_slab_cache)
		return false;
	if (KFENCE_WARN_ON(head != tail))
		return false;
	pr_debug("kfence_free(%px)\n", head);
	if (KFENCE_WARN_ON(aligned_head != page_address(page)))
		return false;
	guarded_free(head);
	return true;
}

size_t kfence_ksize(void *object)
{
	unsigned long flags;
	size_t ret;
	int obj_index = kfence_addr_to_index((unsigned long)object);

	if (obj_index == -1)
		return 0;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	ret = abs(kfence_metadata[obj_index].size);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	return ret;
}

static void kfence_print_stack(int obj_index, bool is_alloc)
{
	unsigned long *entries;
	unsigned long nr_entries;
	depot_stack_handle_t handle;

	if (is_alloc)
		handle = kfence_metadata[obj_index].alloc_stack;
	else
		handle = kfence_metadata[obj_index].free_stack;
	if (handle) {
		nr_entries = stack_depot_fetch(handle, &entries);
		stack_trace_print(entries, nr_entries, 0);
	} else {
		pr_err("  no %s stack.\n",
		       is_alloc ? "allocation" : "deallocation");
	}
}

static void kfence_dump_object(int obj_index)
{
	int size = abs(kfence_metadata[obj_index].size);
	unsigned long start = kfence_index_to_addr(obj_index);

	pr_err("Object #%d: starts at %px, size=%d\n", obj_index, (void *)start,
	       size);
	pr_err("allocated at:\n");
	kfence_print_stack(obj_index, true);
	if (kfence_metadata[obj_index].state == KFENCE_OBJECT_FREED) {
		pr_err("freed at:\n");
		kfence_print_stack(obj_index, false);
	}
}

static inline void kfence_report_oob(unsigned long address, int obj_index)
{
	unsigned long object = kfence_index_to_addr(obj_index);
	bool is_left = address < object;

	pr_err("==================================================================\n");
	pr_err("BUG: KFENCE: slab-out-of-bounds at address %px to the %s of object #%d\n",
	       (void *)address, is_left ? "left" : "right", obj_index);
	dump_stack();
	kfence_dump_object(obj_index);
	pr_err("==================================================================\n");
}

static inline void kfence_report_uaf(unsigned long address, int obj_index)
{
	pr_err("==================================================================\n");
	pr_err("BUG: KFENCE: use-after-free at address %px on object #%d\n",
	       (void *)address, obj_index);
	dump_stack();
	kfence_dump_object(obj_index);
	pr_err("==================================================================\n");
}

bool kfence_handle_page_fault(unsigned long addr)
{
	int page_index, obj_index, report_index = -1, dist = 0, ndist;
	unsigned long flags;

	if ((addr < kfence_pool_start) || (addr >= kfence_pool_end))
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
			kfence_report_oob(addr, report_index);
		} else {
			pr_err("BUG: KFENCE: wild redzone access.\n");
			/* Let the kernel deal with it. */
			spin_unlock_irqrestore(&kfence_alloc_lock, flags);
			return false;
		}
	} else {
		report_index = kfence_addr_to_index(addr);
		kfence_report_uaf(addr, report_index);
		/* TODO: do nothing for now. */
	}
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	/*
	 * Let the kernel proceed.
	 * TODO: either disable KFENCE here, or reinstate the protection later.
	 */
	return kfence_unprotect(addr);
}

void kfence_cache_register(struct kmem_cache *s)
{
	unsigned long flags;
	int index;
	const char *name;

	if (!s)
		return;

	if (!s->name)
		name = "ANON";
	else
		name = s->name;

	if (s->size > PAGE_SIZE) {
		pr_debug("skipping cache %s because of size: %d\n", name,
			 s->size);
		return;
	}
	if (s->ctor) {
		pr_debug("skipping cache %s because of ctor\n", name);
		return;
	}
	if (s->flags & SLAB_TYPESAFE_BY_RCU) {
		pr_debug("skipping cache %s because of RCU\n", name);
		return;
	}
	pr_debug("registering cache %s\n", name);
	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (kfence_num_caches == KFENCE_MAX_CACHES)
		goto leave;
	index = find_cache(s);
	if (index == -1) {
		kfence_registered_caches[kfence_num_caches - 1] = s;
		kfence_num_caches++;
	}
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}
EXPORT_SYMBOL(kfence_cache_register);

/*
 * TODO: tear down objects from the deleted cache. We may want to store a
 * bitmask of KFENCE objects for every registered cache.
 */
void kfence_cache_unregister(struct kmem_cache *s)
{
	unsigned long flags;
	int index;

	if (!s)
		return;

	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (kfence_num_caches == 0)
		goto leave;
	index = find_cache(s);
	if (index == -1)
		goto leave;
	if (index == kfence_num_caches - 1)
		kfence_registered_caches[index] = NULL;
	else
		kfence_registered_caches[index] =
			kfence_registered_caches[kfence_num_caches - 1];
	kfence_num_caches--;
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}
EXPORT_SYMBOL(kfence_cache_unregister);


static struct kmem_cache *kfence_pick_cache(void)
{
	int index;
	struct kmem_cache *cache;

	if (!kfence_num_caches)
		return NULL;
	index = prandom_u32_max(kfence_num_caches);
	do {
		cache = kfence_registered_caches[index];
		index = (index + 1) % kfence_num_caches;
	} while (!cache);

	return cache;
}

static void steal_freelist(void)
{
	struct kmem_cache_cpu *c;
	struct kmem_cache *cache;
	unsigned long flags;
	struct stored_freelist *fl;

	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (num_stored_freelists == STORED_FREELISTS)
		goto leave;
	fl = find_freelist(NULL);
	cache = kfence_pick_cache();
	if (!cache)
		goto leave;
	if (find_freelist(cache))
		goto leave;
	c = raw_cpu_ptr(cache->cpu_slab);
	if (KFENCE_WARN_ON(!c))
		goto leave;
	fl->freelist = c->freelist;
	fl->cache = cache;
	num_stored_freelists++;
	/* TODO: should locking/atomics be involved? */
	c->freelist = 0;
	pr_debug("stole freelist from cache %s on CPU%d!\n", cache->name,
		 smp_processor_id());
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}

static void kfence_arm_heartbeat(struct timer_list *timer)
{
	unsigned long delay = msecs_to_jiffies(kfence_sample_rate);

	mod_timer(timer, jiffies + delay);
}

static void kfence_heartbeat(struct timer_list *timer)
{
	if (!READ_ONCE(kfence_enabled))
		return;

	steal_freelist();
	kfence_arm_heartbeat(timer);
}

/* TODO: make this function part of SLAB API. */
int alloc_kmem_cache_cpus(struct kmem_cache *s);

void __init kfence_init(void)
{
	if (!kfence_sample_rate)
		/* The tool is disabled. */
		return;

	alloc_kmem_cache_cpus(&kfence_slab_cache);
	if (allocate_pool()) {
		WRITE_ONCE(kfence_enabled, true);
		kfence_arm_heartbeat(&kfence_timer);
		pr_info("kfence_init done\n");
	} else {
		pr_err("kfence_init failed\n");
	}
}
EXPORT_SYMBOL(kfence_init);
