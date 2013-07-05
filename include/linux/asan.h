#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

void asan_init_shadow(void);

/*
 * If user asks to poison region [left, right), the program poisons
 * at least [left, align_down(right)).
 * If user asks to unpoison region [left, right), the program unpoisons
 * at most [AlignDown(left), right).
 */
void asan_poison(void *addr, unsigned long size);
void asan_unpoison(void *addr, unsigned long size);

/*
 * Returns pointer to the first poisoned byte if the region is poisoned,
 * returns NULL otherwise.
 */
void *asan_region_is_poisoned(void *addr, unsigned long size);

void asan_on_kernel_init(void);

#endif
