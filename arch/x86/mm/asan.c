#include <linux/asan.h>
#include <asm/page.h>

extern unsigned long max_pfn;

static void *get_shadow(void *addr)
{
        if(addr < __va(0) || addr >= __va(max_pfn << PAGE_SHIFT))
                return NULL;
        return (void*)((unsigned long)(addr - PAGE_OFFSET) / 8 + PAGE_OFFSET + (64<<20));
}

void asan_poison(void *addr, unsigned long size)
{
}

void asan_unpoison(void *addr, unsigned long size)
{
}

void asan_check(void *addr, unsigned long size)
{
}
