#ifndef __X86_MM_ASAN_ASAN_H
#define __X86_MM_ASAN_ASAN_H

#include <linux/slab.h>
#include <linux/types.h>

#define ASAN_COLORED_OUTPUT_ENABLE 0

#define ASAN_SHADOW_OFFSET ((unsigned long)CONFIG_ASAN_SHADOW_OFFSET)
#define ASAN_SHADOW_SCALE 3
#define ASAN_SHADOW_GRAIN (1UL << ASAN_SHADOW_SCALE)

#define ASAN_HEAP_REDZONE 0xfa
#define ASAN_HEAP_KMALLOC_REDZONE 0xfb
#define ASAN_HEAP_FREE 0xfd
#define ASAN_SHADOW_GAP 0xfe

/* The number of frames that will be saved for alloc and free stacks. */
#define ASAN_STACK_TRACE_FRAMES 16
#define ASAN_STACK_TRACE_SIZE (ASAN_STACK_TRACE_FRAMES * sizeof(unsigned long))

#define ASAN_MAX_STACK_TRACE_FRAMES 64

struct redzone {
	unsigned int alloc_stack[ASAN_STACK_TRACE_FRAMES];
	unsigned int free_stack[ASAN_STACK_TRACE_FRAMES];

	int alloc_thread_id;
	int free_thread_id;

	struct list_head quarantine_list;

	/* Size of the kmalloc or krealloc if they were used for allocation. */
	size_t kmalloc_size;
};

#define ASAN_REDZONE_SIZE sizeof(struct redzone)
#define ASAN_QUARANTINE_SIZE \
	(((unsigned long)(CONFIG_ASAN_QUARANTINE_SIZE)) << 20)

/* FIXME: no redzones in 4MB cache. */
#define ASAN_HAS_REDZONE(cache) ((cache)->object_size < (4 << 20))
#define ASAN_OBJECT_TO_REDZONE(cache, object) \
	((void *)(object) + round_up((cache)->object_size, ASAN_SHADOW_GRAIN))
#define ASAN_REDZONE_TO_OBJECT(cache, redzone) \
	((void *)(redzone) - round_up((cache)->object_size, ASAN_SHADOW_GRAIN))

extern int asan_error_counter;
extern spinlock_t asan_error_counter_lock;

void noasan_cache_free(struct kmem_cache *cachep, void *objp,
		       unsigned long caller);

unsigned int asan_compress_and_save_stack_trace(unsigned int *stack,
						unsigned int max_entries,
						unsigned long strip_addr);

unsigned long asan_mem_to_shadow(unsigned long addr);
unsigned long asan_shadow_to_mem(unsigned long shadow_addr);

struct access_info {
	/* XXX: unsigned long access_addr? */
	unsigned long poisoned_addr;
	size_t access_size;
	bool is_write;
	int thread_id;
	unsigned long strip_addr;
};

void asan_report_error(struct access_info *info);
void asan_report_user_access(struct access_info *info);

#endif
