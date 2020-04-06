/* KFENCE implementation */

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <linux/mm.h> // required by slub_def.h, should be included there.
#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/spinlock_types.h>
#include <linux/stackdepot.h>
#include <linux/timer.h>

static void kfence_heartbeat(struct timer_list *timer);
static DEFINE_TIMER(kfence_timer, kfence_heartbeat);

#define STORED_FREELISTS 8
struct stored_freelist {
	struct kmem_cache *cache;
	void *freelist;
};

enum kfence_object_state { KOS_UNUSED, KOS_ALLOCATED, KOS_FREED };

struct alloc_metadata {
	depot_stack_handle_t alloc_stack, free_stack;
	/* >0: left alignment, <0: right alignment. */
	int size;
	enum kfence_object_state state;
};

/* Protects kfence pool state. */
static DEFINE_SPINLOCK(kfence_lock);

DEFINE_PER_CPU(struct stored_freelist[STORED_FREELISTS], stored_freelists);
DEFINE_PER_CPU(int, num_stored_freelists);
DEFINE_PER_CPU(struct kmem_cache *, stored_cache);
struct kmem_cache kfence_slab_cache;
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
struct kfence_freelist_t kfence_freelist, kfence_recycle;

struct alloc_metadata *kfence_metadata;

#define KFENCE_SAMPLING_MS 113
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

/* TODO(glider): kernel_physical_mapping_change() is x86-only */
unsigned long kernel_physical_mapping_change(unsigned long start,
					     unsigned long end,
					     unsigned long page_size_mask);

/* TODO: need to separate away code that splits physical mappings. */
static void __meminit kfence_protect(unsigned long addr)
{
	unsigned long addr_end;
	pte_t *pte;
	unsigned int level;
	unsigned long psize, pmask;
	int split_page_size_mask;

	addr_end = addr + PAGE_SIZE;
	pte = lookup_address(addr, &level);
	BUG_ON(!pte);
	if (level != PG_LEVEL_4K) {
		psize = page_level_size(level);
		pmask = page_level_mask(level);
		split_page_size_mask = 1 << PG_LEVEL_4K;
		kernel_physical_mapping_change(__pa(addr & pmask),
					       __pa((addr_end & pmask) + psize),
					       split_page_size_mask);
		flush_tlb_all();
		pte = lookup_address(addr, &level);
	}
	BUG_ON(level != PG_LEVEL_4K);
	set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
	__flush_tlb_one_kernel(addr);
}

static void __meminit kfence_unprotect(unsigned long addr)
{
	unsigned long addr_end;
	pte_t *pte;
	unsigned int level;

	addr_end = addr + PAGE_SIZE;
	pte = lookup_address(addr, &level);
	BUG_ON(!pte);
	BUG_ON(level != PG_LEVEL_4K);
	set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
	__flush_tlb_one_kernel(addr);
}

static void __meminit allocate_pool(void)
{
	struct page *pages;
	struct kfence_freelist_t *objects;
	unsigned long addr;
	int i;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_ZERO;
	unsigned long flags;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	pages = alloc_pages(GFP_KERNEL, KFENCE_NUM_OBJ_LOG + 1);
	kfence_pool_start = (unsigned long)page_address(pages);
	kfence_pool_end =
		kfence_pool_start + (KFENCE_NUM_OBJ + 1) * 2 * PAGE_SIZE;
	pr_info("kfence allocated pages: %px--%px\n", kfence_pool_start,
		kfence_pool_end);
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
	addr += PAGE_SIZE; // skip the first page: metadata
	kfence_protect(addr); // first redzone
	addr += PAGE_SIZE;
	objects = (struct kfence_freelist_t *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct kfence_freelist_t), gfp_flags);
	for (i = 0; i < KFENCE_NUM_OBJ; i++) {
		if (i == KFENCE_NUM_OBJ)
			objects[i].list.next = NULL;
		else
			objects[i].list.next = &(objects[i + 1].list);
		objects[i].obj = (void *)addr;
		kfence_protect(addr + PAGE_SIZE); // redzone
		addr += 2 * PAGE_SIZE;
	}
	kfence_freelist.list.next = (void *)(&objects[0].list);
	kfence_freelist.list.prev = (void *)(&objects[KFENCE_NUM_OBJ].list);

	/* Set up metadata nodes. */
	kfence_metadata = (struct alloc_metadata *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct alloc_metadata), gfp_flags);
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
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

void *guarded_alloc(size_t size)
{
	unsigned long flags;
	void *obj = NULL, *ret;
	struct kfence_freelist_t *item;
	int index;

	BUG_ON(size > PAGE_SIZE);
	spin_lock_irqsave(&kfence_alloc_lock, flags);

	if (!list_empty(&kfence_freelist.list)) {
		item = list_entry(kfence_freelist.list.next,
				  struct kfence_freelist_t, list);
		obj = item->obj;
		kfence_freelist.list.next = item->list.next;
		list_add(&(item->list), &kfence_recycle.list);
	}

	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
	if (obj) {
		/*
		 * TODO: randomply place the object at the beginning/end of the
		 * page.
		 */
		ret = (void *)((char *)obj + PAGE_SIZE - size);
		index = kfence_addr_to_index(obj);
		BUG_ON(index > KFENCE_NUM_OBJ - 1);
		kfence_metadata[index].alloc_stack = save_stack(GFP_KERNEL);
		kfence_metadata[index].size = -size;
		kfence_metadata[index].state = KOS_ALLOCATED;
	} else {
		ret = NULL;
	}
	pr_debug("guarded_alloc(%d) returns %px\n", size, ret);
	return ret;
}

void guarded_free(void *addr)
{
	unsigned long flags;
	void *aligned_addr = (void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE);
	struct kfence_freelist_t *item;
	int index;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	item = list_entry(kfence_recycle.list.next, struct kfence_freelist_t,
			  list);
	item->obj = aligned_addr;
	kfence_recycle.list.next = item->list.next;
	list_add(&(item->list), &kfence_freelist.list);
	index = kfence_addr_to_index((unsigned long)addr);
	kfence_metadata[index].free_stack = save_stack(GFP_KERNEL);
	kfence_metadata[index].state = KOS_FREED;
	spin_unlock_irqrestore(&kfence_alloc_lock, flags);
}

static int find_freelist(struct kmem_cache *c)
{
	int i;
	for (i = 0; i < STORED_FREELISTS; i++) {
		if (this_cpu_read(stored_freelists[i].cache) == c)
			return i;
	}
	return -1;
}

void *kfence_alloc_and_fix_freelist(struct kmem_cache *s)
{
	unsigned long flags;
	struct kmem_cache_cpu *c = raw_cpu_ptr(s->cpu_slab);
	int fl, num_fl;
	void *ret = NULL;
	void *freelist;

	fl = find_freelist(s);
	if (fl == -1)
		return NULL;
	spin_lock_irqsave(&kfence_lock, flags);
	fl = find_freelist(s);
	if (fl == -1)
		goto leave;
	freelist = this_cpu_read(stored_freelists[fl].freelist);
	ret = guarded_alloc(s->size);
	c->freelist = freelist;
	num_fl = this_cpu_read(num_stored_freelists);
	this_cpu_write(stored_freelists[fl].cache, NULL);
	this_cpu_write(num_stored_freelists, num_fl - 1);
	spin_unlock_irqrestore(&kfence_lock, flags);
	pr_debug("kfence_alloc_and_fix_freelist returns %px\n", ret);
	return ret;
leave:
	spin_unlock_irqrestore(&kfence_lock, flags);
	return NULL;
}

bool kfence_free(struct kmem_cache *s, struct page *page, void *head,
		 void *tail, int cnt, unsigned long addr)
{
	void *aligned_head = (void *)ALIGN_DOWN((unsigned long)head, PAGE_SIZE);

	if (s != &kfence_slab_cache)
		return false;
	BUG_ON(head != tail);
	pr_debug("kfence_free(%px)\n", head);
	BUG_ON(aligned_head != page_address(page));
	guarded_free(head);
	return true;
}

size_t kfence_ksize(void *object)
{
	char *upper = (void *)ALIGN((unsigned long)object, PAGE_SIZE);
	return upper - (char *)object;
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

	pr_err("Object #%d: starts at %px, size=%d\n", obj_index, start, size);
	pr_err("allocated at:\n");
	kfence_print_stack(obj_index, true);
	if (kfence_metadata[obj_index].state == KOS_FREED) {
		pr_err("freed at:\n");
		kfence_print_stack(obj_index, true);
	}
}

static inline void kfence_report_oob(unsigned long address, int obj_index)
{
	unsigned long object = kfence_index_to_addr(obj_index);
	bool is_left = address < object;

	pr_err("BUG: KFENCE: slab-out-of-bounds at address %px to the %s of object #%d\n",
	       address, is_left ? "left" : "right", obj_index);
	dump_stack();
	kfence_dump_object(obj_index);
}

bool kfence_handle_page_fault(unsigned long addr)
{
	int page_index, obj_index, report_index = -1, dist = 0, ndist;
	unsigned long flags;

	if ((addr < kfence_pool_start) || (addr >= kfence_pool_end))
		return false;

	spin_lock_irqsave(&kfence_lock, flags);
	page_index = (addr - kfence_pool_start) / PAGE_SIZE;
	if (page_index % 2) {
		/* This is a redzone, report a buffer overflow. */
		if (page_index > 1) {
			obj_index = kfence_addr_to_index(addr - PAGE_SIZE);
			if (kfence_metadata[obj_index].state == KOS_ALLOCATED) {
				report_index = obj_index;
				dist = addr -
				       (kfence_index_to_addr(obj_index) +
					abs(kfence_metadata[obj_index].size));
			}
		}
		if (page_index < (KFENCE_NUM_OBJ + 1) * 2) {
			obj_index = kfence_addr_to_index(addr + PAGE_SIZE);
			if (kfence_metadata[obj_index].state == KOS_ALLOCATED) {
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
			spin_unlock_irqrestore(&kfence_lock, flags);
			return false;
		}
	} else {
		/* This is a freed object, report a use-after-free. */
		/* TODO: do nothing for now. */
	}
	spin_unlock_irqrestore(&kfence_lock, flags);
	/*
	 * Let the kernel proceed.
	 * TODO: either disable KFENCE here, or reinstate the protection later.
	 */
	kfence_unprotect(addr);
	return true;
}

static void steal_freelist(void)
{
	struct kmem_cache_cpu *c;
	struct kmem_cache *cache;
	unsigned long int index;
	unsigned long flags;
	int num_stored, fl;

	num_stored = this_cpu_read(num_stored_freelists);
	if (num_stored == STORED_FREELISTS)
		return;

	spin_lock_irqsave(&kfence_lock, flags);
	num_stored = this_cpu_read(num_stored_freelists);
	if (num_stored == STORED_FREELISTS)
		goto leave;
	fl = find_freelist(NULL);
	/* TODO: need a random number here. */
	index = (jiffies / 13) % (KMALLOC_SHIFT_HIGH - 2 - KMALLOC_SHIFT_LOW) +
		KMALLOC_SHIFT_LOW;

	cache = kmalloc_caches[0][index];
	if (!cache) {
		pr_info("kmalloc_caches[0][%ld] is NULL!\n", index);
		BUG_ON(!cache);
	}
	if (find_freelist(cache) != -1)
		goto leave;
	c = raw_cpu_ptr(cache->cpu_slab);
	BUG_ON(!c);
	this_cpu_write(stored_freelists[fl].freelist, c->freelist);
	this_cpu_write(stored_freelists[fl].cache, cache);
	this_cpu_write(num_stored_freelists, num_stored + 1);
	this_cpu_write(stored_cache, cache);
	/* TODO: should locking/atomics be involved? */
	c->freelist = 0;
	pr_debug("stole freelist from cache %s on CPU%d!\n", cache->name,
		 smp_processor_id());
leave:
	spin_unlock_irqrestore(&kfence_lock, flags);
}

static void kfence_arm_heartbeat(struct timer_list *timer)
{
	unsigned long delay = msecs_to_jiffies(KFENCE_SAMPLING_MS);

	mod_timer(timer, jiffies + delay);
}

static void kfence_heartbeat(struct timer_list *timer)
{
	steal_freelist();
	kfence_arm_heartbeat(timer);
}

/* TODO: make this function part of SLAB API. */
int alloc_kmem_cache_cpus(struct kmem_cache *s);

void __init kfence_init(void)
{
	spin_lock_init(&kfence_lock);
	spin_lock_init(&kfence_alloc_lock);
	INIT_LIST_HEAD(&kfence_freelist.list);
	INIT_LIST_HEAD(&kfence_recycle.list);
	memset(&kfence_slab_cache, 0, sizeof(struct kmem_cache));
	kfence_slab_cache.name = "kfence_slab_cache";
	alloc_kmem_cache_cpus(&kfence_slab_cache);
	kfence_slab_cache.flags = SLAB_KFENCE;
	allocate_pool();
	kfence_arm_heartbeat(&kfence_timer);
	pr_info("kfence_init done\n");
}
EXPORT_SYMBOL(kfence_init);
