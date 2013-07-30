#ifndef ASAN_POISONING_H_
#define ASAN_POISONING_H_

#include <linux/types.h>

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to SHADOW_GRANULARITY.
 */
void asan_poison_shadow(const void *addr, unsigned long size, u8 value);
void asan_unpoison_shadow(const void *addr, unsigned long size);

/*
 * Returns pointer to the first poisoned byte if the region is in memory
 * and poisoned, returns NULL otherwise.
 */
const void *asan_region_is_poisoned(const void *addr, unsigned long size);

#endif
