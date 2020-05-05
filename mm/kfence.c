// SPDX-License-Identifier: GPL-2.0

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/spinlock_types.h>
#include <linux/stackdepot.h>
#include <linux/timer.h>

#include "slab.h"

/* Usually on, unless explicitly disabled. */
static bool kfence_enabled;

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
static struct kmem_cache *kfence_registered_caches[KFENCE_MAX_CACHES];
static int kfence_num_caches;

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
static struct stored_freelist stored_freelists[STORED_FREELISTS];
static int num_stored_freelists;

/*
 * It's handy (but not strictly required) that 255 objects with redzones occupy
 * exactly 2Mb.
 */
#define KFENCE_NUM_OBJ_LOG 8
#define KFENCE_NUM_OBJ ((1 << KFENCE_NUM_OBJ_LOG) - 1)

static unsigned long kfence_pool_start, kfence_pool_end;

/* Protects kfence_freelist, kfence_recycle, kfence_metadata */
static DEFINE_SPINLOCK(kfence_alloc_lock);

struct kfence_freelist {
	struct list_head list;
	void *obj;
};
/*
 * kfence_freelist is a wrapper around kfence page pointers that allows
 * chaining them.
 * @kfence_freelist is a FIFO queue of non-allocated pages, @kfence_recycle is
 * a stack of unused kfence_freelist objects.
 * When allocating a new object in guarded_alloc(), a kfence_freelist item is
 * taken from the queue and its @kfence_freelist.obj member is used for
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

static noinline void kfence_disable(void)
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

bool is_kfence_addr(unsigned long addr)
{
	return ((addr >= kfence_pool_start) && (addr < kfence_pool_end));
}
EXPORT_SYMBOL(is_kfence_addr);

/* Does not require kfence_alloc_lock. */
static inline int kfence_addr_to_index(unsigned long addr)
{
	if (!is_kfence_addr(addr))
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

void *guarded_alloc(struct kmem_cache *cache, gfp_t gfp)
{
	unsigned long flags;
	void *obj = NULL, *ret;
	struct kfence_freelist *item;
	int index = -1;
	bool right = prandom_u32_max(2);
	size_t size = cache->size;
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
	pr_debug("guarded_alloc(%ld) returns %px\n", size, ret);
	pr_debug("allocated object #%d\n", index);
	return ret;
}

void guarded_free(void *addr)
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

/* Requires kfence_caches_lock. */
bool kfence_fix_freelist(struct kmem_cache *s)
{
	struct kmem_cache_cpu *c = raw_cpu_ptr(s->cpu_slab);
	struct stored_freelist *fl;
	void *freelist;

	fl = find_freelist(s);
	if (fl == NULL)
		return false;
	freelist = fl->freelist;
	c->freelist = freelist;
	fl->cache = NULL;
	num_stored_freelists--;
	return true;
}

void *kfence_alloc_and_fix_freelist(struct kmem_cache *s, gfp_t gfp)
{
	unsigned long flags;
	void *ret = NULL;

	if (!READ_ONCE(kfence_enabled))
		return NULL;
	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (!kfence_fix_freelist(s))
		goto leave;
	ret = guarded_alloc(s, gfp);
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

	if (!is_kfence_addr((unsigned long)head))
		return false;
	if (KFENCE_WARN_ON(head != tail))
		return false;
	pr_debug("kfence_free(%px)\n", head);
	if (KFENCE_WARN_ON(aligned_head != page_address(page)))
		return false;
	guarded_free(head);
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
		len += snprintf(buf + len, buf_size - len, "  no %s stack.\n",
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

	len += snprintf(buf + len, buf_size - len,
			"Object #%d: starts at %px, size=%d\n", obj_index,
			(void *)start, size);
	len += snprintf(buf + len, buf_size - len, "allocated at:\n");
	len += kfence_dump_stack(buf + len, buf_size - len, obj, true);
	if (kfence_metadata[obj_index].state == KFENCE_OBJECT_FREED) {
		len = snprintf(buf + len, buf_size - len, "freed at:\n");
		len = kfence_dump_stack(buf + len, buf_size - len, obj, false);
	}
	cache = kfence_metadata[obj_index].cache;
	if (cache && cache->name)
		len += snprintf(buf + len, buf_size - len,
				"Object #%d belongs to cache %s\n", obj_index,
				cache->name);
	return len;
}

static void kfence_print_object(int obj_index, struct alloc_metadata *obj)
{
	struct page *buf_page;
	const int order = 2;
	char *buf;

	buf_page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!buf_page)
		return;
	buf = page_address(buf_page);
	kfence_dump_object(buf, PAGE_SIZE << order, obj_index, obj);
	pr_err("%s", buf);

	__free_pages(buf_page, order);
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

	if (!is_kfence_addr(addr))
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

void kfence_cache_register(struct kmem_cache *s)
{
	unsigned long flags;
	int index;
	const char *name;
	struct kmem_cache *root;

	if (!s)
		return;

	if (!s->name)
		name = "ANON";
	else
		name = s->name;

#ifdef CONFIG_MEMCG
	/*
	 * There are too many memcg child caches, tracking them would require
	 * too many resources and would reduce the probability of stealing a
	 * freelist from an "interesting" cache.
	 * See kfence_observe_memcg_cache() for details about memcg cache
	 * handling.
	 */
	root = s->memcg_params.root_cache;
	if (root) {
		pr_debug("skipping memcg cache %s\n", s->name);
		return;
	}
#endif

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

bool kfence_discard_slab(struct kmem_cache *s, struct page *page)
{
	if (!is_kfence_addr((unsigned long)page_address(page)))
		return false;
	/* Nothing here for now, but maybe we need to free the objects. */
	return true;
}

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
	kfence_fix_freelist(s);
	if (index != kfence_num_caches - 1)
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

/* Requires kfence_caches_lock. */
static void kfence_steal_freelist(struct kmem_cache *cache)
{
	struct stored_freelist *fl;
	struct kmem_cache_cpu *c;

	if (num_stored_freelists == STORED_FREELISTS)
		return;
	if (find_freelist(cache))
		return;
	fl = find_freelist(NULL);
	c = raw_cpu_ptr(cache->cpu_slab);
	if (KFENCE_WARN_ON(!c))
		return;
	fl->freelist = c->freelist;
	fl->cache = cache;
	num_stored_freelists++;
	/* TODO: should locking/atomics be involved? */
	c->freelist = 0;
	pr_debug("stole freelist from cache %s on CPU%d!\n", cache->name,
		 smp_processor_id());
}

#ifdef CONFIG_MEMCG
/*
 * Tracking all caches created by memory cgroups may be hard, as there are lots
 * of them. Instead, we only track root (non-memcg) caches. If an allocation is
 * done from a memcg cache, we check if we stole the freelist from its root. In
 * that case we restore the freelist of the root cache and steal the freelist of
 * the memcg cache.
 *
 * TODO: this function is called for every memcg allocation, need to speed it
 * up. Memcg allocations aren't popular in the kernel though.
 * */
void kfence_observe_memcg_cache(struct kmem_cache *memcg_cache)
{
	unsigned long flags;
	struct kmem_cache *root;
	char *name;

	if (!memcg_cache)
		return;

	if (memcg_cache->name)
		name = (char *)memcg_cache->name;
	else
		name = "ANON";

	root = memcg_cache->memcg_params.root_cache;

	if (!root)
		/* This is not a valid memcg child cache. */
		return;

	spin_lock_irqsave(&kfence_caches_lock, flags);
	if (kfence_fix_freelist(root)) {
		kfence_steal_freelist(memcg_cache);
		pr_debug("stole freelist from memcg cache %s\n",
			 memcg_cache->name);
	}
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}
EXPORT_SYMBOL(kfence_observe_memcg_cache);
#endif

static void steal_random_freelist(void)
{
	struct kmem_cache *cache;
	unsigned long flags;

	spin_lock_irqsave(&kfence_caches_lock, flags);
	cache = kfence_pick_cache();
	if (!cache)
		goto leave;
	kfence_steal_freelist(cache);
leave:
	spin_unlock_irqrestore(&kfence_caches_lock, flags);
}

static void kfence_heartbeat(struct timer_list *timer)
{
	if (!READ_ONCE(kfence_enabled))
		return;

	steal_random_freelist();
	mod_timer(timer, jiffies + msecs_to_jiffies(kfence_sample_rate));
}
static DEFINE_TIMER(kfence_timer, kfence_heartbeat);

void __init kfence_init(void)
{
	if (!kfence_sample_rate)
		/* The tool is disabled. */
		return;

	if (allocate_pool()) {
		WRITE_ONCE(kfence_enabled, true);
		mod_timer(&kfence_timer, jiffies + 1);
		pr_info("kfence_init done\n");
	} else {
		pr_err("kfence_init failed\n");
	}
}
