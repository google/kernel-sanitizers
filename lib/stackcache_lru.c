// SPDX-License-Identifier: GPL-2.0
/*
 * LRU-cache based implementation for stackcache.
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
#include <linux/mm.h>

#define PER_CPU_HASH_TABLE_SIZE_BITS 13
#define PER_CPU_HASH_TABLE_ENTRIES (1 << 10)
#define PER_CPU_RING_BUFFER_SIZE (1 << 21)
#define STACK_CACHE_HASH_SEED 0xDEADBEEF

#define RING_BUFFER_SUB_POS(pos, cnt)                                                              \
	((pos) + PER_CPU_RING_BUFFER_SIZE - (cnt)) & (PER_CPU_RING_BUFFER_SIZE - 1)

#define for_each_rb_entry(buffer, hdr, start_pos, space_offset)                                    \
	for (used_space = 0,                                                                       \
	    hdr = (typeof(hdr)) &                                                                  \
		  buffer[RING_BUFFER_SUB_POS(start_pos, space_offset + sizeof(*hdr))],             \
	    space_offset += hdr->length;                                                           \
	     space_offset <= PER_CPU_RING_BUFFER_SIZE && hdr->record_type != BUF_RECORD_EMPTY;     \
	     hdr = (typeof(hdr)) &                                                                 \
		   buffer[RING_BUFFER_SUB_POS(start_pos, space_offset + sizeof(*hdr))],            \
	    space_offset += hdr->length)

enum buf_record_type {
	BUF_RECORD_EMPTY = 0, /* Not set yet */
	BUF_RECORD_INFO,
	BUF_RECORD_STACK,
	BUF_RECORD_SKIP
};

struct buf_record_hdr {
	u16 record_type : 2; /* See enum buf_record_type. */
	u16 length : 14; /* Number of bytes in the record */
} __packed;

/* A record that stores a memory operation (e.g. alloc/dealloc). */
struct buf_info_record {
	u16 trace_type;
	u32 size;
	u32 hash;
	u32 time_jiffies;
	unsigned long ptr;
} __packed;

/* A record that stores an evicted stack trace. */
struct buf_stack_record {
	u32 trace_count;
	u32 trace_hash;
	unsigned long stack_trace[];
} __packed;

/* An entry of the LRU cache. */
struct stackcache_lru_entry {
	struct hlist_node ht_node;
	struct list_head lru_node;
	u32 trace_hash;
	size_t trace_count;
	unsigned long stack_trace[STACK_CACHE_MAX_DEPTH];
};

struct stackcache_cpu_ctx {
	spinlock_t lock;

	/* Ring buffer fields */
	u8 *buffer;
	size_t next_idx;

	/* Hashtable fields */
	DECLARE_HASHTABLE(lru_table, PER_CPU_HASH_TABLE_SIZE_BITS);
	struct list_head lru_list;
	struct stackcache_lru_entry *lru_entries;
	size_t n_lru_entries;
};

/* TODO: Is it guaranteed that this struct is zeroed by default? */
static DEFINE_PER_CPU(struct stackcache_cpu_ctx, stackcache_ctx);

/* ===== Internals ====================================================*/

static struct stackcache_lru_entry *find_lru_cache_entry(struct stackcache_cpu_ctx *ctx, u32 hash)
{
	struct stackcache_lru_entry *record;
	hash_for_each_possible (ctx->lru_table, record, ht_node, hash) {
		if (record->trace_hash == hash)
			return record;
	}

	return NULL;
}

/*
 * Allocates space for a new entry and returns a pointer to its first byte. This function ensures
 * that the object will get a contiguous memory chunk.
 * It is achieved by introducing a special type of records - BUF_RECORD_SKIP. If the entry to be
 * added wraps the end of the buffer, a record of that type is inserted first. As a result, it
 * becomes possible to put the new record at the beginning of the buffer.
 */
static inline void *add_new_record(struct stackcache_cpu_ctx *ctx, size_t len, u16 record_type)
{
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
 * Store and deduplicate stack traces.
 *
 * 1. Check the LRU cache, if the entry is there, update the cache.
 * 2. Otherwise, push an evicted entry to the round buffer. Insert a new one.
 * 3. Return the hash of the entry
 */
static inline u32 store_stack_trace(struct stackcache_cpu_ctx *ctx, size_t n_entries,
				    const unsigned long *entries)
{
	struct stackcache_lru_entry *entry;
	const unsigned long *trace_begin;
	size_t entries_total_size;
	u32 trace_hash;

	/* Take the last STACK_CACHE_MAX_DEPTH entries. */
	if (n_entries <= STACK_CACHE_MAX_DEPTH) {
		trace_begin = entries;
	} else {
		trace_begin = entries + (STACK_CACHE_MAX_DEPTH - n_entries);
		n_entries = STACK_CACHE_MAX_DEPTH;
	}

	entries_total_size = n_entries * sizeof(unsigned long);
	trace_hash =
		jhash2((u32 *)trace_begin, entries_total_size / sizeof(u32), STACK_CACHE_HASH_SEED);

	entry = find_lru_cache_entry(ctx, trace_hash);
	if (entry != NULL) {
		/* Make it the most recently used. */
		list_del(&entry->lru_node);
	} else {
		if (ctx->n_lru_entries == PER_CPU_HASH_TABLE_ENTRIES) {
			__maybe_unused struct buf_stack_record *record;
			size_t __maybe_unused total_size;

			entry = list_first_entry(&ctx->lru_list, struct stackcache_lru_entry,
						 lru_node);
			list_del(&entry->lru_node);
			hash_del(&entry->ht_node);

#ifndef STACKCACHE_LRU_NO_VICTIM_CACHE
			total_size = offsetof(struct buf_stack_record, stack_trace) +
				     entry->trace_count * sizeof(unsigned long);
			record = add_new_record(ctx, total_size, BUF_RECORD_STACK);
			record->trace_count = entry->trace_count;
			record->trace_hash = entry->trace_hash;
			memcpy(&record->stack_trace, entry->stack_trace,
			       entry->trace_count * sizeof(unsigned long));
#endif
		} else {
			entry = &ctx->lru_entries[ctx->n_lru_entries++];
		}

		entry->trace_hash = trace_hash;
		hash_add(ctx->lru_table, &entry->ht_node, trace_hash);
		memcpy(&entry->stack_trace, trace_begin, entries_total_size);
		entry->trace_count = n_entries;
	}
	list_add_tail(&entry->lru_node, &ctx->lru_list);

	return trace_hash;
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
	dist = ((u8 *)ptr + size) - (u8 *)entry->object;
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
				    struct stack_cache_response *new_resp)
{
	new_resp->object = (void *)info_record->ptr;
	new_resp->size = info_record->size;
	new_resp->trace_type = info_record->trace_type;
	new_resp->time_jiffies = (u32)jiffies - info_record->time_jiffies;
	new_resp->n_entries = 0;
	/* Temporarily store the hash in the first stack trace entry. */
	new_resp->entries[0] = info_record->hash;
}

static void set_traces_from_lru(struct stackcache_cpu_ctx *ctx,
				struct stack_cache_response *entries, unsigned int nentries)
{
	int i;
	for (i = 0; i < nentries; i++) {
		struct stackcache_lru_entry *entry;
		if (entries[i].n_entries > 0)
			continue;

		entry = find_lru_cache_entry(ctx, entries[i].entries[0]);
		if (entry) {
			entries[i].n_entries = entry->trace_count;
			memcpy(&entries[i].entries, &entry->stack_trace,
			       entry->trace_count * sizeof(unsigned long));
		}
	}
}

#ifndef STACKCACHE_LRU_NO_VICTIM_CACHE
static void set_traces_from_record(struct stack_cache_response *entries, unsigned int nentries,
				   struct buf_stack_record *record)
{
	int i;
	for (i = 0; i < nentries; i++) {
		if (entries[i].n_entries > 0 || entries[i].entries[0] != record->trace_hash)
			continue;

		entries[i].n_entries = record->trace_count;
		memcpy(&entries[i].entries, &record->stack_trace,
		       record->trace_count * sizeof(unsigned long));
	}
}
#endif

static int __init stack_cache_init(void)
{
	int cpu;

	/* Ensure that the sizes allow to be sure that buf_record_hdr never wraps the end. */
	BUILD_BUG_ON(PER_CPU_RING_BUFFER_SIZE % sizeof(struct buf_record_hdr));
	BUILD_BUG_ON(sizeof(struct buf_info_record) % sizeof(struct buf_record_hdr));

	for_each_possible_cpu (cpu) {
		void *buffer_ptr = kvzalloc(PER_CPU_RING_BUFFER_SIZE, GFP_KERNEL);
		struct stackcache_cpu_ctx *ctx = &per_cpu(stackcache_ctx, cpu);
		void *entries_ptr =
			kvzalloc(PER_CPU_HASH_TABLE_ENTRIES * sizeof(struct stackcache_lru_entry),
				 GFP_KERNEL);

		WRITE_ONCE(ctx->lru_entries, entries_ptr);
		hash_init(ctx->lru_table);
		INIT_LIST_HEAD(&ctx->lru_list);
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
	unsigned long flags;
	u32 trace_hash;

	ctx = get_cpu_ptr(&stackcache_ctx);

	/* If it is not initialized yet. */
	if (unlikely(READ_ONCE(ctx->buffer) == NULL))
		goto error;

	/* Just skip the insertion if the CPU is already doing it. */
	if (spin_trylock_irqsave(&ctx->lock, flags) == 0)
		goto error;

	trace_hash = store_stack_trace(ctx, n_entries, entries);
	record = add_new_record(ctx, sizeof(*record), BUF_RECORD_INFO);
	record->trace_type = trace_type;
	record->size = size;
	record->ptr = (unsigned long)object;
	record->hash = trace_hash;
	record->time_jiffies = (u32)jiffies;

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

	for_each_possible_cpu (cpu) {
		struct stackcache_cpu_ctx *ctx = &per_cpu(stackcache_ctx, cpu);
		char *buffer = READ_ONCE(ctx->buffer);
		struct buf_record_hdr *hdr;
		int used_space = 0;
		int next_idx;

		/* Check if it's initialized. */
		if (buffer == NULL)
			continue;

		spin_lock(&ctx->lock);
		next_idx = READ_ONCE(ctx->next_idx);

		/* Traverse info records. */
		for_each_rb_entry(buffer, hdr, next_idx, used_space)
		{
			struct stack_cache_response new_resp;
			size_t start_pos;
			size_t insert_at;

			if (hdr->record_type != BUF_RECORD_INFO)
				continue;

			start_pos = RING_BUFFER_SUB_POS(next_idx, used_space);
			info_record_to_response((struct buf_info_record *)&buffer[start_pos],
						&new_resp);

			/* Do insertion sort. */
			insert_at = ret_entries;
			while (insert_at > 0 &&
			       is_less(&new_resp, &entries[insert_at - 1], ptr, size))
				insert_at--;

			if (insert_at < nentries) {
				ret_entries = min_t(size_t, ret_entries + 1, nentries);
				insert_element(entries, ret_entries, insert_at, &new_resp);
			}
		}

		/* Set traces from the LRU cache. */
		set_traces_from_lru(ctx, entries, ret_entries);

		/* Set traces from trace records. */
#ifndef STACKCACHE_LRU_NO_VICTIM_CACHE
		next_idx = READ_ONCE(ctx->next_idx);
		for_each_rb_entry(buffer, hdr, next_idx, used_space)
		{
			size_t pos;
			if (hdr->record_type != BUF_RECORD_STACK)
				continue;
			pos = RING_BUFFER_SUB_POS(next_idx, used_space);
			set_traces_from_record(entries, nentries,
					       (struct buf_stack_record *)&buffer[pos]);
		}
#endif

		spin_unlock(&ctx->lock);
	}

	return ret_entries;
}

early_initcall(stack_cache_init);
