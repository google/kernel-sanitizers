#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

#include <linux/types.h>

#define ASAN_USER_POISONED_MEMORY 0xF7
#define ASAN_HEAP_REDZONE 0xFA
#define ASAN_HEAP_FREE 0xFD

#define SHADOW_SCALE 3
#define SHADOW_OFFSET 0x36600000
#define SHADOW_GRANULARITY (1 << SHADOW_SCALE)

#define ASAN_REDZONE_SIZE 32

extern int asan_enabled;

/*
 * Reserves shadow memory.
 */
void asan_init_shadow(void);

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be properly aligned.
 */
void asan_poison_shadow(const void *addr, unsigned long size, u8 value);
void asan_unpoison_shadow(const void *addr, unsigned long size);

/*
 * If user asks to poison region [left, right), the program poisons
 * at least [left, align_down(right)).
 * If user asks to unpoison region [left, right), the program unpoisons
 * at most [AlignDown(left), right).
 */
void asan_poison_memory(const void *addr, unsigned long size);
void asan_unpoison_memory(const void *addr, unsigned long size);

/*
 * Returns pointer to the first poisoned byte if the region is poisoned,
 * returns NULL otherwise.
 */
const void *asan_region_is_poisoned(const void *addr, unsigned long size);

/*
 * Checks region for poisoned bytes.
 * Reports poisoned bytes if found.
 */
void asan_check_region(const void *addr, unsigned long size);

void asan_on_kernel_init(void);

void asan_on_memcpy(const void *to, const void *from, unsigned long n);

#endif /* LINUX_ASAN_H */
