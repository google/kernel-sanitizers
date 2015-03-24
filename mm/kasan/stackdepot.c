/*
 * Stack depot
 * KASAN needs to safe alloc and free stacks per object, but storing 2 stack
 * traces per object is too much overhead (e.g. SLUB_DEBUG needs 256 bytes per
 * object).
 *
 * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
 * and free stacks repeat a lot, we save about 100x space.
 * Stacks are never removed from depot, so we store them contiguously one after
 * another in a contiguos memory allocation.
 */


#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

#include "kasan.h"


#define STACK_ALLOC_ORDER 4 /* 'Slab' size order for stack depot, 16 pages */
#define STACK_ALLOC_SIZE (1L << (PAGE_SHIFT + STACK_ALLOC_ORDER))
#define STACK_ALLOC_GFP_MASK (__GFP_WAIT | __GFP_IO | __GFP_FS | \
			      __GFP_NOWARN | __GFP_NORETRY | \
			      __GFP_NOMEMALLOC | __GFP_NO_KSWAPD )
#define STACK_ALLOC_ALIGN 4
#define STACK_ALLOC_OFFSET_BITS (STACK_ALLOC_ORDER + PAGE_SHIFT - \
				 STACK_ALLOC_ALIGN)
#define STACK_ALLOC_INDEX_BITS (KASAN_STACK_BITS - STACK_ALLOC_OFFSET_BITS)
#define STACK_ALLOC_MAX_SLABS (1L << STACK_ALLOC_INDEX_BITS)

/* The compact structure to store the reference to stacks. */
union handle_parts {
	kasan_stack_handle handle;
	struct {
		u32 slabindex : STACK_ALLOC_INDEX_BITS;
		u32 offset : STACK_ALLOC_OFFSET_BITS;
	};
};

struct kasan_stack {
	struct kasan_stack *next;	/* Link in the hashtable */
	u32 hash;			/* Hash in the hastable */
	u32 size;			/* Number of frames in the stack */
	union handle_parts handle;
	unsigned long entries[1];	/* Variable-sized array of entries. */
};

static void *stack_slabs[STACK_ALLOC_MAX_SLABS] = {
	[0 ... STACK_ALLOC_MAX_SLABS - 1] = NULL
};

static int depot_index;
static size_t depot_offset;
static DEFINE_SPINLOCK(depot_lock);

/* Allocation of a new stack in raw storage */
static struct kasan_stack *kasan_alloc_stack(unsigned long *entries, int size,
				      u32 hash, gfp_t alloc_flags)
{
	int required_size = offsetof(struct kasan_stack, entries) +
		sizeof(unsigned long) * size;
	struct kasan_stack *stack;

	required_size = ALIGN(required_size, 1 << STACK_ALLOC_ALIGN);

	if (unlikely(depot_offset + required_size > STACK_ALLOC_SIZE)) {
		if (unlikely(depot_index + 1 >= STACK_ALLOC_MAX_SLABS)) {
			pr_err("Stack depot reached limit capacity");
			return NULL;
		}
		depot_index++;
		depot_offset = 0;
	}

	if (unlikely(!stack_slabs[depot_index])) {
		struct page *page = alloc_pages(
				alloc_flags & STACK_ALLOC_GFP_MASK,
				STACK_ALLOC_ORDER);

		if (unlikely(!page)) {
			pr_warn("Failed to allocate stack in kasan depot");
			return NULL;
		}
		stack_slabs[depot_index] = page_address(page);
	}

	stack = stack_slabs[depot_index] + depot_offset;

	stack->hash = hash;
	stack->size = size;
	stack->handle.slabindex = depot_index;
	stack->handle.offset = depot_offset >> STACK_ALLOC_ALIGN;
	__memcpy(stack->entries, entries, size * sizeof(unsigned long));
	depot_offset += required_size;

	return stack;
}

#define STACK_HASH_ORDER 20
#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
#define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
#define STACK_HASH_SEED 0x9747b28c

static struct kasan_stack *stack_table[STACK_HASH_SIZE] = {
	[0 ...	STACK_HASH_SIZE - 1] = NULL
};

/* Calculate hash for a stack */
static inline u32 hash_stack(unsigned long *entries, unsigned int size)
{
	return jhash2((u32 *)entries,
			       size * sizeof(unsigned long) / sizeof(u32),
			       STACK_HASH_SEED);
}

/* Find a stack that is equal to the one stored in entries in the hash */
static inline struct kasan_stack *find_stack(struct kasan_stack *bucket,
					     unsigned long *entries, int size,
					     u32 hash)
{
	struct kasan_stack *found;

	for (found = bucket; found; found = found->next) {
		if (found->hash == hash &&
		    found->size == size &&
		    !memcmp(entries, found->entries,
			    size * sizeof(unsigned long))) {
			return found;
		}
	}
	return NULL;
}

void kasan_fetch_stack(kasan_stack_handle handle, struct stack_trace *trace)
{
	union handle_parts parts = { .handle = handle };
	void *slab = stack_slabs[parts.slabindex];
	size_t offset = parts.offset << STACK_ALLOC_ALIGN;
	struct kasan_stack *stack = slab + offset;

	trace->nr_entries = trace->max_entries = stack->size;
	trace->entries = stack->entries;
	trace->skip = 0;
}

/*
 * kasan_save_stack - save stack in a stack depot.
 * @trace - the stacktrace to save.
 * @alloc_flags - flags for allocating additional memory if required.
 *
 * Returns the handle of the stack struct stored in depot.
 */
kasan_stack_handle kasan_save_stack(struct stack_trace *trace,
				    gfp_t alloc_flags)
{
	u32 hash;
	struct kasan_stack *found, **bucket;
	unsigned long flags;

	if (unlikely(trace->nr_entries == 0))
		return 0;

	hash = hash_stack(trace->entries, trace->nr_entries);
	bucket = &stack_table[hash & STACK_HASH_MASK];

	found = find_stack(smp_load_acquire(bucket), trace->entries,
			   trace->nr_entries, hash);
	if (found)
		return found->handle.handle;

	spin_lock_irqsave(&depot_lock, flags);

	found = find_stack(*bucket, trace->entries, trace->nr_entries, hash);
	if (!found) {
		struct kasan_stack *new =
			kasan_alloc_stack(trace->entries, trace->nr_entries,
					  hash, alloc_flags);

		if (new) {
			new->next = *bucket;
			smp_store_release(bucket, new);
		}
		found = new;
	}

	spin_unlock_irqrestore(&depot_lock, flags);

	if (found)
		return found->handle.handle;
	else
		return 0;
}

