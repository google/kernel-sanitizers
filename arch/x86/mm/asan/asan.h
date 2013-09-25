#ifndef __X86_MM_ASAN_ASAN_H
#define __X86_MM_ASAN_ASAN_H

#include <linux/slab.h>
#include <linux/types.h>

#define ASAN_HEAP_REDZONE 0xfa
#define ASAN_HEAP_KMALLOC_REDZONE 0xfb
#define ASAN_HEAP_FREE 0xfd
#define ASAN_SHADOW_GAP 0xfe

#define ASAN_SHADOW_SCALE 3UL
#define ASAN_SHADOW_OFFSET 0x36400600UL
#define ASAN_SHADOW_GRANULARITY (1UL << ASAN_SHADOW_SCALE)

/* The number of frames that will be saved for alloc and free stacks. */
#define ASAN_STACK_TRACE_FRAMES 16
#define ASAN_STACK_TRACE_SIZE (ASAN_STACK_TRACE_FRAMES * sizeof(unsigned long))

#define ASAN_MAX_STACK_TRACE_FRAMES 64

struct chunk {
	struct kmem_cache *cache;
	void *object;
	struct list_head list;
};

struct asan_redzone {
	unsigned long alloc_stack[ASAN_STACK_TRACE_FRAMES];
	unsigned long free_stack[ASAN_STACK_TRACE_FRAMES];

	/* XXX: use pid_t? */
	int alloc_thread_id;
	int free_thread_id;

	struct chunk chunk;
	unsigned long quarantine_flag;

	/*
	 * Size of the kmalloc or krealloc.
	 * 0 if the object was allocated another way.
	 */
	unsigned long kmalloc_size;
};

#define ASAN_REDZONE_SIZE sizeof(struct asan_redzone)

#define ASAN_QUARANTINE_SIZE (128 << 20)

#define ASAN_COLORED_OUTPUT_ENABLE 0

extern int asan_error_counter;
extern spinlock_t asan_error_counter_lock;

pid_t asan_current_thread_id(void);

unsigned int asan_save_stack_trace(unsigned long *stack,
				   unsigned int max_entries);

unsigned long asan_mem_to_shadow(unsigned long addr);
unsigned long asan_shadow_to_mem(unsigned long shadow_addr);

/* Checks region for poisoned bytes. Reports poisoned bytes if found. */
void asan_check_memory_region(const void *addr, unsigned long size, bool write);

void asan_report_error(unsigned long poisoned_addr,
		       unsigned long access_size, bool is_write);

#endif
