// KFENCE api

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KFENCE
/* TODO: API documentation */

void kfence_init(void);

void *kfence_alloc_and_fix_freelist(struct kmem_cache *s);

bool kfence_free(struct kmem_cache *s, struct page *page, void *head,
		 void *tail, int cnt, unsigned long addr);

size_t kfence_ksize(void *object);

bool kfence_handle_page_fault(unsigned long address);

#else
static inline void kfence_init(void)
{
}
static inline void *kfence_alloc_and_fix_freelist(struct kmem_cache *s)
{
	return NULL;
}
static inline bool kfence_free(struct kmem_cache *s, struct page *page,
			       void *head, void *tail, int cnt,
			       unsigned long addr)
{
	return false;
}
static size_t kfence_ksize(void *object)
{
	return 0;
}
bool kfence_handle_page_fault(unsigned long address)
{
	return false;
}
#endif
