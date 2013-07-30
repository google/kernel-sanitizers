#ifndef ASAN_POISONING_H_
#define ASAN_POISONING_H_

#include <linux/types.h>

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

int asan_memory_is_poisoned(unsigned long addr);

#endif
