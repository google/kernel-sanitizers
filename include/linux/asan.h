#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

void asan_init_shadow(void);

void asan_poison(void *addr, unsigned long size);
void asan_unpoison(void *addr, unsigned long size);

void* asan_region_is_poisoned(void *addr, unsigned long size);
void asan_ensure_region_is_poisoned(void* addr, unsigned long size);

void asan_on_kernel_init(void);

#endif
