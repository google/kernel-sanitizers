// SPDX-License-Identifier: GPL-2.0
/*
 * Ring buffer-based implementation for stackcache.
 *
 * Copyright (C) 2020, Google Inc.
 */

#include <linux/stackcache.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/list.h>

#define PER_CPU_RING_BUFFER_SIZE (1<<22)
#define STACK_CACHE_HASH_SEED 0xDEADBEEF

#define RING_BUFFER_SUB_POS(pos, cnt) ((pos) + PER_CPU_RING_BUFFER_SIZE - (cnt)) \
	& (PER_CPU_RING_BUFFER_SIZE - 1)

enum buf_record_type {
	BUF_RECORD_EMPTY = 0, /* Not set yet */
	BUF_RECORD_INFO,
	BUF_RECORD_SKIP
};

struct buf_record_hdr {
	u16 record_type:2;	/* See enum buf_record_type. */
	u16 length:14;		/* Number of bytes in the record */
} __packed;

/* A record that stores a memory operation (e.g. alloc/dealloc). */
struct buf_info_record {
	unsigned long ptr;
	u32 size;
	u32 time_jiffies;
	u32 trace_count;
	u16 trace_type;
	unsigned long stack_trace[];
} __packed;

struct stackcache_cpu_ctx {
	spinlock_t lock;

	/* Ring buffer fields */
	u8 *buffer;
	size_t next_idx;
};

/* TODO: Is it guaranteed that this struct is zeroed by default? */
static DEFINE_PER_CPU(struct stackcache_cpu_ctx, stackcache_ctx);

/* ===== Internals ====================================================*/

/*
 * Allocates space for a new entry and returns a pointer to its first byte. This function ensures
 * that the object will get a contiguous memory chunk.
 * It is achieved by introducing a special type of records - BUF_RECORD_SKIP. If the entry to be
 * added wraps the end of the buffer, a record of that type is inserted first. As a result, it
 * becomes possible to put the new record at the beginning of the buffer.
 */
static inline void* add_new_record(struct stackcache_cpu_ctx *ctx, size_t len, u16 record_type) {
	u8 *buffer = READ_ONCE(ctx->buffer);
	size_t prev_next = READ_ONCE(ctx->next_idx);
	struct buf_record_hdr *hdr;
	size_t new_next;

	len += sizeof(*hdr);
	new_next = prev_next + len;
	if (unlikely(new_next >= PER_CPU_RING_BUFFER_SIZE)) {
		hdr = (struct buf_record_hdr *)&buffer[PER_CPU_RING_BUFFER_SIZE - sizeof(*hdr)];
		hdr->record_type = BUF_RECORD_SKIP;
		hdr->length = PER_CPU_RING_BUFFER_SIZE - prev_next;
		new_next = len;
	}

	hdr = (struct buf_record_hdr *)&buffer[new_next - sizeof(*hdr)];
	hdr->record_type = record_type;
	hdr->length = len;
	WRITE_ONCE(ctx->next_idx, new_next);
	return &buffer[new_next - len];
}

/*
 * Calculate the distance from [@ptr; @ptr+@size] to the object described by @entry.
 */
static unsigned long distance_to(struct stack_cache_response *entry, const volatile void *ptr,
								 size_t size)
{
	unsigned long dist;

	/* XX....[object] */
	if (ptr < entry->object)
		return (u8 *)entry->object - (u8 *)ptr;

	/* [object]..XX, [objectX]X, or [objectXX] */
	dist = ((u8*)ptr + size) - (u8*)entry->object;
	if (dist > entry->size)
		return dist - entry->size;
	return 0;
}

/*
 * Check if left and right follow the ordering wanted by stack_cache_lookup().
 */
static bool is_less(struct stack_cache_response *left, struct stack_cache_response *right,
						   const volatile void *ptr, size_t size)
{
	unsigned long distance_left = distance_to(left, ptr, size);
	unsigned long distance_right = distance_to(right, ptr, size);
	if (distance_left != distance_right)
		return distance_left < distance_right;

	/* Break ties by time */
	return left->time_jiffies < right->time_jiffies;
}

/*
 * Insert an element into an array of struct stack_cache_response.
 */
static void insert_element(struct stack_cache_response *entries, unsigned int nentries,
						   size_t insert_at, struct stack_cache_response *new_entry)
{
	WARN_ON(insert_at >= nentries);
	if (insert_at + 1 < nentries) {
		memmove(&entries[insert_at + 1], &entries[insert_at],
				sizeof(*new_entry) * (nentries - insert_at - 1));
	}
	memcpy(&entries[insert_at], new_entry, sizeof(*new_entry));
}

/*
 * Convert struct buf_info_record to struct stack_cache_response
 */
static void info_record_to_response(struct buf_info_record *info_record,
									struct stack_cache_response *new_resp) {
	new_resp->object = (void *)info_record->ptr;
	new_resp->size = info_record->size;
	new_resp->trace_type = info_record->trace_type;
	new_resp->time_jiffies = (u32)jiffies - info_record->time_jiffies;
	new_resp->n_entries = info_record->trace_count;
	memcpy(new_resp->entries, info_record->stack_trace,
		   info_record->trace_count * sizeof(unsigned long));
}

static int __init stack_cache_init(void)
{
	int cpu;

	/* Ensure that the sizes allow to be sure that buf_record_hdr never wraps the end. */
	BUILD_BUG_ON(PER_CPU_RING_BUFFER_SIZE % sizeof(struct buf_record_hdr));
	BUILD_BUG_ON(offsetof(struct buf_info_record, stack_trace) % sizeof(struct buf_record_hdr));

	for_each_possible_cpu(cpu) {
		void *buffer_ptr = kzalloc(PER_CPU_RING_BUFFER_SIZE, GFP_KERNEL);
		struct stackcache_cpu_ctx *ctx = &per_cpu(stackcache_ctx, cpu);
		spin_lock_init(&ctx->lock);

		/* Enable stack_cache_insert(). */
		wmb();
		WRITE_ONCE(ctx->buffer, buffer_ptr);
	}

	return 0;
}

/* ===== Public methods =================================================== */

void stack_cache_insert(const volatile void *object, size_t size, unsigned trace_type,
						size_t n_entries, const unsigned long *entries)
{
	struct stackcache_cpu_ctx *ctx;
	struct buf_info_record *record;
	const unsigned long *trace_begin;
	unsigned long flags;
	size_t record_size;

	/* Take the last STACK_CACHE_MAX_DEPTH entries. */
	if (n_entries <= STACK_CACHE_MAX_DEPTH) {
		trace_begin = entries;
	} else {
		trace_begin = entries + (STACK_CACHE_MAX_DEPTH - n_entries);
		n_entries = STACK_CACHE_MAX_DEPTH;
	}

	ctx = get_cpu_ptr(&stackcache_ctx);

	/* If it is not initialized yet. */
	if (unlikely(READ_ONCE(ctx->buffer) == NULL))
	    goto error;

	/* Just skip the insertion if the CPU is already doing it. */
	if (spin_trylock_irqsave(&ctx->lock, flags) == 0)
		goto error;

	record_size = offsetof(struct buf_info_record, stack_trace) + n_entries * sizeof(unsigned long);
	record = add_new_record(ctx, record_size, BUF_RECORD_INFO);
	record->trace_type = trace_type;
	record->size = size;
	record->ptr = (unsigned long)object;
	record->time_jiffies = (u32)jiffies;
	record->trace_count = n_entries;
	memcpy(&record->stack_trace, trace_begin, n_entries * sizeof(unsigned long));

	spin_unlock_irqrestore(&ctx->lock, flags);
error:
	put_cpu_ptr(&stackcache_ctx);
}

size_t stack_cache_lookup(const volatile void *ptr, size_t size,
						  struct stack_cache_response *entries, unsigned int nentries)
{
	int cpu;
	size_t ret_entries = 0;

	if (nentries <= 1)
		return 0;

	for_each_possible_cpu(cpu) {
		struct stackcache_cpu_ctx *ctx = &per_cpu(stackcache_ctx, cpu);
		int next_idx;
		char *buffer = READ_ONCE(ctx->buffer);
		int used_space = 0;

		/* Check if it's initialized. */
		if (buffer == NULL)
			continue;

		spin_lock(&ctx->lock);
		next_idx = READ_ONCE(ctx->next_idx);

		while (true) {
			size_t hdr_pos = RING_BUFFER_SUB_POS(next_idx, sizeof(struct buf_record_hdr));
			struct buf_record_hdr *hdr = (struct buf_record_hdr *)&buffer[hdr_pos];
			struct stack_cache_response new_resp;
			int insert_at;

			if (used_space + hdr->length > PER_CPU_RING_BUFFER_SIZE
				|| hdr->record_type == BUF_RECORD_EMPTY)
				break;

			used_space += hdr->length;
			next_idx = RING_BUFFER_SUB_POS(next_idx, hdr->length);
			if (hdr->record_type == BUF_RECORD_SKIP)
				continue;

			info_record_to_response((struct buf_info_record *)&buffer[next_idx], &new_resp);

			/* Do insertion sort. */
			insert_at = ret_entries;
			while (insert_at > 0 && is_less(&new_resp, &entries[insert_at - 1], ptr, size))
				insert_at--;

			if (insert_at < nentries) {
				ret_entries = min_t(size_t, ret_entries + 1, nentries);
				insert_element(entries, ret_entries, insert_at, &new_resp);
			}
		}

		spin_unlock(&ctx->lock);
	}

	return ret_entries;
}

core_initcall(stack_cache_init);
