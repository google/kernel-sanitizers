#ifndef LINUX_ASAN_H
#define LINUX_ASAN_H

void asan_poison(void *addr, unsigned long size);
void asan_unpoison(void *addr, unsigned long size);
void asan_check(void *addr, unsigned long size);

#endif
