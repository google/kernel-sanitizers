// KFENCE api

#ifdef CONFIG_KFENCE
void kfence_init(void);
void *kfence_alloc_and_fix_freelist(struct kmem_cache *s);
bool kfence_free(struct kmem_cache *s, struct page *page,
		 void *head, void *tail, int cnt,
		 unsigned long addr);
size_t kfence_ksize(void *object);

#else
static void kfence_init(void) {}
static void *kfence_alloc_and_fix_freelist(struct kmem_cache *s)
{
	return NULL;
}
static bool kfence_free(struct kmem_cache *s, struct page *page,
		 void *head, void *tail, int cnt,
		 unsigned long addr)
{
	return false;
}

static size_t kfence_ksize(void *object)
{
	return 0;
}
#endif
