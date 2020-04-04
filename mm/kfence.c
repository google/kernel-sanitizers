/* KFENCE implementation */

#include <asm/pgtable.h>
#include <asm/tlbflush.h>

#include <linux/mm.h> // required by slub_def.h, should be included there.
#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/spinlock_types.h>
#include <linux/timer.h>

static void kfence_heartbeat(struct timer_list *timer);
static DEFINE_TIMER(kfence_timer, kfence_heartbeat);

#define STORED_FREELISTS 8
struct stored_freelist {
	struct kmem_cache *cache;
	void *freelist;
};
DEFINE_PER_CPU(struct stored_freelist[STORED_FREELISTS], stored_freelists);
DEFINE_PER_CPU(int, num_stored_freelists);
DEFINE_PER_CPU(struct kmem_cache *, stored_cache);
struct kmem_cache kfence_slab_cache;
EXPORT_SYMBOL(kfence_slab_cache);

static DEFINE_SPINLOCK(kfence_lock);
static DEFINE_SPINLOCK(kfence_alloc_lock);

struct kfence_freelist_t {
	struct list_head list;
	void *obj;
};

/*
 * It's handy (but not strictly required) that 255 objects with redzones occupy
 * exactly 2Mb.
 */
#define KFENCE_NUM_OBJ_LOG 8
#define KFENCE_NUM_OBJ ((1 << KFENCE_NUM_OBJ_LOG) - 1)

#define KFENCE_SAMPLING_MS 113

struct kfence_freelist_t *kfence_comb;
struct list_head kfence_freelist_old;
struct kfence_freelist_t kfence_freelist, kfence_recycle;

/* TODO(glider): kernel_physical_mapping_change() is x86-only */
unsigned long kernel_physical_mapping_change(unsigned long start,
					     unsigned long end,
					     unsigned long page_size_mask);

/* TODO: need to separate away code that splits physical mappings. */
void __meminit kfence_protect(unsigned long addr)
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

/* TODO: comb is a poor analogy, come up with a better term. */
void allocate_comb(void)
{
	struct page *pages;
	struct kfence_freelist_t *objects;
	char *addr; /* TODO: addr is never initialized */
	int i;

	pages = alloc_pages(GFP_KERNEL, KFENCE_NUM_OBJ_LOG + 1);
	pr_info("kfence allocated pages: %px--%px\n", addr,
		addr + (KFENCE_NUM_OBJ + 1) * 2 * PAGE_SIZE);
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
	addr = page_address(pages);
	addr += PAGE_SIZE; // skip the first page: metadata
	kfence_protect(addr); // first redzone
	addr += PAGE_SIZE;
	objects = (struct kfence_freelist_t *)kmalloc_array(
		KFENCE_NUM_OBJ, sizeof(struct kfence_freelist_t), GFP_KERNEL);
	for (i = 0; i < KFENCE_NUM_OBJ; i++) {
		if (i == KFENCE_NUM_OBJ)
			objects[i].list.next = NULL;
		else
			objects[i].list.next = &(objects[i + 1].list);
		objects[i].obj = addr;
		kfence_protect(addr + PAGE_SIZE); // redzone
		addr += 2 * PAGE_SIZE;
	}
	kfence_freelist.list.next = (void *)(&objects[0].list);
	kfence_freelist.list.prev = (void *)(&objects[KFENCE_NUM_OBJ].list);
	kfence_comb = objects;
}

void *guarded_alloc(size_t size)
{
	unsigned long flags;
	void *obj = NULL, *ret;
	struct kfence_freelist_t *item;

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
	if (obj)
		ret = (void *)((char *)obj + PAGE_SIZE - size);
	else
		ret = NULL;
	pr_info("guarded_alloc(%d) returns %px\n", size, ret);
	return ret;
}

void guarded_free(void *addr)
{
	unsigned long flags;
	void *aligned_addr = (void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE);
	struct kfence_freelist_t *item;

	spin_lock_irqsave(&kfence_alloc_lock, flags);
	item = list_entry(kfence_recycle.list.next, struct kfence_freelist_t,
			  list);
	item->obj = aligned_addr;
	kfence_recycle.list.next = item->list.next;
	list_add(&(item->list), &kfence_freelist.list);
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
	struct kmem_cache *stored;
	void *ret = NULL;
	struct page *page;
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
	pr_info("kfence_alloc_and_fix_freelist returns %px\n", ret);
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
	pr_info("kfence_free(%px)\n", head);
	BUG_ON(aligned_head != page_address(page));
	guarded_free(head);
	return true;
}

size_t kfence_ksize(void *object)
{
	char *upper = (void *)ALIGN((unsigned long)object, PAGE_SIZE);
	return upper - (char *)object;
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
	pr_info("stole freelist from cache %s on CPU%d!\n", cache->name,
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
	allocate_comb();
	kfence_arm_heartbeat(&kfence_timer);
	pr_info("kfence_init done\n");
}
EXPORT_SYMBOL(kfence_init);
