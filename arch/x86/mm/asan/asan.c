#include <linux/asan.h>

#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

#include <asm/bug.h>
#include <asm/page.h>
#include <asm/page_64.h>
#include <asm/thread_info.h>

#include "asan.h"

#undef memset
#undef memcpy

static struct {
	int enabled;
	spinlock_t quarantine_lock;
	struct list_head quarantine_list;
	size_t quarantine_size;
} ctx = {
	.enabled = 0,
	.quarantine_lock = __SPIN_LOCK_UNLOCKED(ctx.quarantine_lock),
	.quarantine_list = LIST_HEAD_INIT(ctx.quarantine_list),
	.quarantine_size = 0,
};

static struct kmem_cache *virt_to_cache(const void *ptr)
{
	struct page *page = virt_to_head_page(ptr);
	return page->slab_cache;
}

static int current_thread_id(void)
{
	return current_thread_info()->task->pid;
}

unsigned int asan_compress_and_save_stack_trace(unsigned int *output,
						unsigned int max_entries,
						unsigned long strip_addr)
{
	unsigned long stack[ASAN_MAX_STACK_TRACE_FRAMES];
	unsigned int entries;
	unsigned int beg = 0, end, i;

	struct stack_trace trace_info = {
		.nr_entries = 0,
		.entries = stack,
		.max_entries = ASAN_MAX_STACK_TRACE_FRAMES,
		.skip = 0
	};
	save_stack_trace(&trace_info);
	entries = trace_info.nr_entries;

	while (stack[beg] != strip_addr && beg < entries)
		beg++;
	end = (entries - beg <= max_entries) ? entries : beg + max_entries;

	for (i = 0; i < end - beg; i++)
		output[i] = stack[beg + i] & UINT_MAX;
	return end - beg;
}

static void quarantine_put(struct kmem_cache *cache, void *object)
{
	struct redzone *redzone;
	unsigned long flags;

	if (!ctx.enabled)
		return;

	BUG_ON(!ASAN_HAS_REDZONE(cache));
	redzone = ASAN_OBJECT_TO_REDZONE(cache, object);

	spin_lock_irqsave(&ctx.quarantine_lock, flags);
	list_add(&redzone->quarantine_list, &ctx.quarantine_list);
	ctx.quarantine_size += cache->size;
	spin_unlock_irqrestore(&ctx.quarantine_lock, flags);
}

static void quarantine_flush(void)
{
	struct redzone *redzone;
	struct kmem_cache *cache;
	void *object;
	unsigned long flags;

	spin_lock_irqsave(&ctx.quarantine_lock, flags);

	while (ctx.quarantine_size > ASAN_QUARANTINE_SIZE) {
		BUG_ON(list_empty(&ctx.quarantine_list));

		redzone = list_entry(ctx.quarantine_list.prev,
				     struct redzone, quarantine_list);
		list_del(ctx.quarantine_list.prev);

		cache = virt_to_cache(redzone);
		object = ASAN_REDZONE_TO_OBJECT(cache, redzone);

		ctx.quarantine_size -= cache->size;

		spin_unlock_irqrestore(&ctx.quarantine_lock, flags);
		local_irq_save(flags);
		noasan_cache_free(cache, object, _THIS_IP_);
		local_irq_restore(flags);
		spin_lock_irqsave(&ctx.quarantine_lock, flags);
	}

	spin_unlock_irqrestore(&ctx.quarantine_lock, flags);
}

static void quarantine_drop_cache(struct kmem_cache *cache)
{
	struct list_head *pos, *n;
	struct redzone *redzone;
	void *object;
	unsigned long flags;

	spin_lock_irqsave(&ctx.quarantine_lock, flags);

	list_for_each_safe(pos, n, &ctx.quarantine_list) {
		redzone = list_entry(pos, struct redzone, quarantine_list);
		if (virt_to_cache(redzone) == cache) {
			list_del(pos);

			object = ASAN_REDZONE_TO_OBJECT(cache, redzone);

			ctx.quarantine_size -= cache->size;

			spin_unlock_irqrestore(&ctx.quarantine_lock, flags);
			local_irq_save(flags);
			noasan_cache_free(cache, object, _THIS_IP_);
			local_irq_restore(flags);
			spin_lock_irqsave(&ctx.quarantine_lock, flags);
		}
	}

	spin_unlock_irqrestore(&ctx.quarantine_lock, flags);
}

static bool addr_is_in_mem(unsigned long addr)
{
	return (addr >= (unsigned long)(__va(0)) &&
		addr < (unsigned long)(__va(max_pfn << PAGE_SHIFT)));
}

unsigned long asan_mem_to_shadow(unsigned long addr)
{
	BUG_ON(!addr_is_in_mem(addr));
	return ((addr - PAGE_OFFSET) >> ASAN_SHADOW_SCALE)
		+ PAGE_OFFSET + ASAN_SHADOW_OFFSET;
}

unsigned long asan_shadow_to_mem(unsigned long shadow_addr)
{
	/* TODO: check addr in in shadow. */
	return ((shadow_addr - ASAN_SHADOW_OFFSET - PAGE_OFFSET)
		<< ASAN_SHADOW_SCALE) + PAGE_OFFSET;
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to ASAN_SHADOW_GRAIN.
 */
static void poison_shadow(const void *address, size_t size, u8 value)
{
	unsigned long shadow_beg, shadow_end;
	unsigned long addr = (unsigned long)address;

	BUG_ON(!IS_ALIGNED(addr, ASAN_SHADOW_GRAIN));
	BUG_ON(!IS_ALIGNED(addr + size, ASAN_SHADOW_GRAIN));
	BUG_ON(!addr_is_in_mem(addr));
	BUG_ON(!addr_is_in_mem(addr + size - ASAN_SHADOW_GRAIN));

	shadow_beg = asan_mem_to_shadow(addr);
	shadow_end = asan_mem_to_shadow(addr + size - ASAN_SHADOW_GRAIN) + 1;
	memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

static void unpoison_shadow(const void *address, size_t size)
{
	poison_shadow(address, size, 0);
}

static bool address_is_poisoned(unsigned long addr)
{
	const unsigned long ACCESS_SIZE = 1;
	u8 *shadow_addr = (u8 *)asan_mem_to_shadow(addr);
	s8 shadow_value = *shadow_addr;
	if (shadow_value != 0) {
		u8 last_accessed_byte = (addr & (ASAN_SHADOW_GRAIN - 1))
					+ ACCESS_SIZE - 1;
		return last_accessed_byte >= shadow_value;
	}
	return false;
}

static bool memory_is_zero(const u8 *beg, size_t size)
{
	const u8 *end = beg + size;
	unsigned long beg_addr = (unsigned long)beg;
	unsigned long end_addr = (unsigned long)end;
	unsigned long *aligned_beg =
		(unsigned long *)round_up(beg_addr, sizeof(unsigned long));
	unsigned long *aligned_end =
		(unsigned long *)round_down(end_addr, sizeof(unsigned long));
	unsigned long all = 0;
	const u8 *mem;
	for (mem = beg; mem < (u8 *)aligned_beg && mem < end; mem++)
		all |= *mem;
	for (; aligned_beg < aligned_end; aligned_beg++)
		all |= *aligned_beg;
	if ((u8 *)aligned_end >= beg)
		for (mem = (u8 *)aligned_end; mem < end; mem++)
			all |= *mem;
	return all == 0;
}

/*
 * Returns address of the first poisoned byte if the memory region
 * lies in the physical memory and poisoned, returns 0 otherwise.
 */
static unsigned long memory_is_poisoned(unsigned long addr, size_t size)
{
	unsigned long beg, end;
	unsigned long aligned_beg, aligned_end;
	unsigned long shadow_beg, shadow_end;

	if (size == 0)
		return 0;

	beg = addr;
	end = beg + size;
	if (!addr_is_in_mem(beg) || !addr_is_in_mem(end))
		return 0;

	aligned_beg = round_up(beg, ASAN_SHADOW_GRAIN);
	aligned_end = round_down(end, ASAN_SHADOW_GRAIN);
	shadow_beg = asan_mem_to_shadow(aligned_beg);
	shadow_end = asan_mem_to_shadow(aligned_end);
	if (!address_is_poisoned(beg) &&
	    !address_is_poisoned(end - 1) &&
	    (shadow_end <= shadow_beg ||
	     memory_is_zero((const u8 *)shadow_beg, shadow_end - shadow_beg)))
		return 0;
	for (; beg < end; beg++)
		if (address_is_poisoned(beg))
			return beg;

	BUG(); /* Unreachable. */
	return 0;
}

static void check_memory_region(unsigned long addr, size_t size, bool write)
{
	unsigned long poisoned_addr;
	struct access_info info;

	if (!ctx.enabled)
		return;

	if (addr == 0 || size == 0)
		return;

	if ((addr & (1UL << 63)) == 0) {
		info.poisoned_addr = addr,
		info.access_size = size,
		info.is_write = write,
		info.thread_id = current_thread_id(),
		info.strip_addr = _RET_IP_,
		asan_report_user_access(&info);
		return;
	}

	poisoned_addr = memory_is_poisoned(addr, size);
	if (poisoned_addr == 0)
		return;

	info.poisoned_addr = poisoned_addr,
	info.access_size = size,
	info.is_write = write,
	info.thread_id = current_thread_id(),
	info.strip_addr = _RET_IP_,
	asan_report_error(&info);
}

static void check_memory_word(unsigned long addr, size_t size, bool write)
{
	u8 *shadow_addr;
	s8 shadow_value;
	u8 last_accessed_byte;
	struct access_info info;

	if (!ctx.enabled)
		return;

	if (addr == 0 || size == 0)
		return;

	if ((addr & (1UL << 63)) == 0) {
		info.poisoned_addr = addr,
		info.access_size = size,
		info.is_write = write,
		info.thread_id = current_thread_id(),
		info.strip_addr = _RET_IP_,
		asan_report_user_access(&info);
		return;
	}

	if (!addr_is_in_mem(addr) || !addr_is_in_mem(addr + size))
		return;

	shadow_addr = (u8 *)asan_mem_to_shadow(addr);
	shadow_value = *shadow_addr;
	if (shadow_value == 0)
		return;

	last_accessed_byte = (addr & (ASAN_SHADOW_GRAIN - 1)) + size - 1;
	if (last_accessed_byte < shadow_value)
		return;

	info.poisoned_addr = addr,
	info.access_size = size,
	info.is_write = write,
	info.thread_id = current_thread_id(),
	info.strip_addr = _RET_IP_,
	asan_report_error(&info);
}

void __init asan_init_shadow(void)
{
	unsigned long memory_size = max_pfn << PAGE_SHIFT;
	unsigned long shadow_size = memory_size >> ASAN_SHADOW_SCALE;
	void *memory_beg = (void *)PAGE_OFFSET;
	void *shadow_beg = memory_beg + ASAN_SHADOW_OFFSET;
	unsigned long found_free_range = memblock_find_in_range(
		ASAN_SHADOW_OFFSET, ASAN_SHADOW_OFFSET + shadow_size,
		shadow_size, ASAN_SHADOW_GRAIN);

	pr_err("Shadow offset: %lx\n", ASAN_SHADOW_OFFSET);
	pr_err("Shadow size: %lx\n", shadow_size);

	if (found_free_range != ASAN_SHADOW_OFFSET ||
	    memblock_reserve(ASAN_SHADOW_OFFSET, shadow_size) != 0) {
		pr_err("Error: unable to reserve shadow!\n");
		return;
	}

	unpoison_shadow(memory_beg, memory_size);
	poison_shadow(shadow_beg, shadow_size, ASAN_SHADOW_GAP);

	ctx.enabled = 1;
}

void asan_cache_create(struct kmem_cache *cache, size_t *size)
{
	unsigned long object_size = cache->object_size;
	unsigned long rounded_up_object_size =
		round_up(object_size, sizeof(unsigned long));

	if (ASAN_HAS_REDZONE(cache)) {
		*size += ASAN_REDZONE_SIZE;

		/* Ensure that the cache is large enough. */
		BUG_ON(*size < rounded_up_object_size + ASAN_REDZONE_SIZE);
	}
}

void asan_cache_destroy(struct kmem_cache *cache)
{
	quarantine_drop_cache(cache);
}

void asan_slab_create(struct kmem_cache *cache, void *slab)
{
	poison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT,
			   ASAN_HEAP_REDZONE);
	quarantine_flush();
}

void asan_slab_destroy(struct kmem_cache *cache, void *slab)
{
	unpoison_shadow(slab, (1 << cache->gfporder) << PAGE_SHIFT);
}

void asan_slab_alloc(struct kmem_cache *cache, void *object)
{
	unsigned long addr = (unsigned long)object;
	unsigned long size = cache->object_size;
	unsigned long rounded_down_size = round_down(size, ASAN_SHADOW_GRAIN);
	struct redzone *redzone;
	unsigned int *alloc_stack;
	u8 *shadow;
	unsigned long strip_addr;

	unpoison_shadow(object, rounded_down_size);
	if (rounded_down_size != size) {
		shadow = (u8 *)asan_mem_to_shadow(addr + rounded_down_size);
		*shadow = size & (ASAN_SHADOW_GRAIN - 1);
	}

	if (!ASAN_HAS_REDZONE(cache))
		return;

	redzone = ASAN_OBJECT_TO_REDZONE(cache, object);

	/* Strip asan_slab_alloc and kmem_cache_alloc frames. */
	alloc_stack = redzone->alloc_stack;
	strip_addr = (unsigned long)__builtin_return_address(1);
	asan_compress_and_save_stack_trace(alloc_stack,
		ASAN_STACK_TRACE_FRAMES, strip_addr);

	redzone->alloc_thread_id = current_thread_id();
	redzone->free_thread_id = -1;

	redzone->kmalloc_size = 0;
}

void asan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->object_size;
	unsigned long rounded_up_size = round_up(size, ASAN_SHADOW_GRAIN);
	struct redzone *redzone;
	unsigned int *free_stack;
	unsigned long strip_addr;

	if (cache->flags & SLAB_DESTROY_BY_RCU) {
		noasan_cache_free(cache, object, _THIS_IP_);
		return;
	}

	poison_shadow(object, rounded_up_size, ASAN_HEAP_FREE);

	if (!ASAN_HAS_REDZONE(cache)) {
		noasan_cache_free(cache, object, _THIS_IP_);
		return;
	}

	redzone = ASAN_OBJECT_TO_REDZONE(cache, object);

	/* Strip asan_slab_free and kmem_cache_free frames. */
	free_stack = redzone->free_stack;
	strip_addr = (unsigned long)__builtin_return_address(1);
	asan_compress_and_save_stack_trace(free_stack,
		ASAN_STACK_TRACE_FRAMES, strip_addr);

	redzone->free_thread_id = current_thread_id();

	quarantine_put(cache, object);
}

void asan_kmalloc(struct kmem_cache *cache, void *object, size_t size)
{
	unsigned long addr = (unsigned long)object;
	unsigned long object_size = cache->object_size;
	unsigned long rounded_up_object_size =
		round_up(object_size, ASAN_SHADOW_GRAIN);
	unsigned long rounded_down_kmalloc_size =
		round_down(size, ASAN_SHADOW_GRAIN);
	struct redzone *redzone;
	u8 *shadow;

	if (object == NULL)
		return;

	poison_shadow(object, rounded_up_object_size,
		ASAN_HEAP_KMALLOC_REDZONE);
	unpoison_shadow(object, rounded_down_kmalloc_size);
	if (rounded_down_kmalloc_size != size) {
		shadow = (u8 *)asan_mem_to_shadow(addr +
						  rounded_down_kmalloc_size);
		*shadow = size & (ASAN_SHADOW_GRAIN - 1);
	}

	if (!ASAN_HAS_REDZONE(cache))
		return;
	redzone = ASAN_OBJECT_TO_REDZONE(cache, object);
	redzone->kmalloc_size = size;
}
EXPORT_SYMBOL(asan_kmalloc);

void asan_krealloc(void *object, size_t size)
{
	asan_kmalloc(virt_to_cache(object), object, size);
}

size_t asan_ksize(const void *ptr)
{
	struct kmem_cache *cache;
	const struct redzone *redzone;

	BUG_ON(!ptr);
	if (unlikely(ptr == ZERO_SIZE_PTR))
		return 0;

	cache = virt_to_cache(ptr);
	if (ASAN_HAS_REDZONE(cache)) {
		redzone = ASAN_OBJECT_TO_REDZONE(cache, ptr);
		if (redzone->kmalloc_size) {
			BUG_ON(redzone->kmalloc_size > cache->object_size);
			return redzone->kmalloc_size;
		}
	}
	return cache->object_size;
}
EXPORT_SYMBOL(asan_ksize);

void *asan_memcpy(void *dst, const void *src, size_t len)
{
	char *d = (char *)dst;
	const char *s = (const char *)src;
	size_t i;

	check_memory_region((unsigned long)src, len, false);
	check_memory_region((unsigned long)dst, len, true);

	for (i = 0; i < len; i++)
		d[i] = s[i];
	return dst;
}
EXPORT_SYMBOL(asan_memcpy);

void *asan_memset(void *ptr, int val, size_t len)
{
	char *p = (char *)ptr;
	size_t i;

	check_memory_region((unsigned long)ptr, len, true);

	for (i = 0; i < len; i++)
		p[i] = val;
	return ptr;
}
EXPORT_SYMBOL(asan_memset);

void *asan_memmove(void *dst, const void *src, size_t len)
{
	char *d = (char *)dst;
	const char *s = (const char *)src;
	long i;

	check_memory_region((unsigned long)src, len, false);
	check_memory_region((unsigned long)dst, len, true);

	if (d < s) {
		for (i = 0; i < len; i++)
			d[i] = s[i];
	} else {
		if (d > s && len > 0)
			for (i = len - 1; i >= 0; i--)
				d[i] = s[i];
	}
	return dst;
}
EXPORT_SYMBOL(asan_memmove);

void __kasan_read1(unsigned long addr)
{
	check_memory_word(addr, 1, false);
}
EXPORT_SYMBOL(__kasan_read1);

void __kasan_read2(unsigned long addr)
{
	check_memory_word(addr, 2, false);
}
EXPORT_SYMBOL(__kasan_read2);

void __kasan_read4(unsigned long addr)
{
	check_memory_word(addr, 4, false);
}
EXPORT_SYMBOL(__kasan_read4);

void __kasan_read8(unsigned long addr)
{
	check_memory_word(addr, 8, false);
}
EXPORT_SYMBOL(__kasan_read8);

void __kasan_read16(unsigned long addr)
{
	check_memory_region(addr, 16, false);
}
EXPORT_SYMBOL(__kasan_read16);

void __kasan_write1(unsigned long addr)
{
	check_memory_word(addr, 1, true);
}
EXPORT_SYMBOL(__kasan_write1);

void __kasan_write2(unsigned long addr)
{
	check_memory_word(addr, 2, true);
}
EXPORT_SYMBOL(__kasan_write2);

void __kasan_write4(unsigned long addr)
{
	check_memory_word(addr, 4, true);
}
EXPORT_SYMBOL(__kasan_write4);

void __kasan_write8(unsigned long addr)
{
	check_memory_word(addr, 8, true);
}
EXPORT_SYMBOL(__kasan_write8);

void __kasan_write16(unsigned long addr)
{
	check_memory_region(addr, 16, true);
}
EXPORT_SYMBOL(__kasan_write16);
