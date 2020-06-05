#ifndef MM_KFENCE_H
#define MM_KFENCE_H

extern bool kfence_enabled;
extern unsigned long kfence_sample_rate;

void *kfence_guarded_alloc(struct kmem_cache *cache, size_t override_size,
			   gfp_t gfp);
void kfence_guarded_free(void *addr);
void kfence_disable(void);
bool __meminit kfence_allocate_pool(void);

/* Should be provided by the sampling algorithm implementation. */
void kfence_impl_init(void);

#define KFENCE_WARN_ON(cond)                                                   \
	({                                                                     \
		bool __cond = WARN_ON(cond);                                   \
		if (unlikely(__cond))                                          \
			kfence_disable();                                      \
		__cond;                                                        \
	})

#endif /* MM_KFENCE_H */
