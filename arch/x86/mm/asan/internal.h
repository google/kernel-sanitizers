#ifndef ASAN_INTERNAL_H_
#define ASAN_INTERNAL_H_

#include "quarantine.h"

#define ASAN_HEAP_REDZONE 0xFA
#define ASAN_HEAP_FREE 0xFD

/* XXX: add UL? */
#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x36600000
#define SHADOW_GRANULARITY (1 << SHADOW_SCALE)

/* The number of frames that will be saved for alloc and free stacks. */
#define ASAN_FRAMES_IN_STACK_TRACE 16
#define ASAN_STACK_TRACE_SIZE \
	(ASAN_FRAMES_IN_STACK_TRACE * sizeof(unsigned long))

struct asan_redzone {
	unsigned long alloc_stack[ASAN_FRAMES_IN_STACK_TRACE];
	unsigned long free_stack[ASAN_FRAMES_IN_STACK_TRACE];
	/* XXX: use pid_t? */
	int alloc_thread_id;
	int free_thread_id;
	struct chunk chunk;
};

#define ASAN_REDZONE_SIZE sizeof(struct asan_redzone)

#define ASAN_QUARANTINE_ENABLE 0
#define ASAN_QUARANTINE_SIZE (1 << 10)

#define ASAN_COLORED_OUTPUT_ENABLE 1

extern int asan_enabled;

/*
 * Checks region for poisoned bytes.
 * Reports poisoned bytes if found.
 */
void asan_check_region(const void *addr, unsigned long size);

#endif
