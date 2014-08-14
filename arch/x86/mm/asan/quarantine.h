#ifndef __X86_MM_ASAN_QUARANTINE_H
#define __X86_MM_ASAN_QUARANTINE_H

#include <linux/types.h>

struct kmem_cache;

void asan_quarantine_init(void);
void asan_quarantine_put(struct kmem_cache *cache, void *object);
void asan_quarantine_flush(void);
void asan_quarantine_drop_cache(struct kmem_cache *cache);
size_t asan_quarantine_size(void);

#endif  // __X86_MM_ASAN_QUARANTINE_H
