#include <asm/page.h>
#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/asan.h>

#include "utils.h"

extern unsigned long max_pfn;

#define SHADOW_SCALE (3)
#define SHADOW_OFFSET (64 << 20)
#define SHADOW_GRANULARITY (1 << SHADOW_SCALE)

#define ASAN_POISONED_MEMORY 0xF7

static uptr mem_to_shadow(uptr addr)
{
        if (addr < (uptr)(__va(0)) || addr >= (uptr)(__va(max_pfn << PAGE_SHIFT)))
                return 0;
        return ((addr - PAGE_OFFSET) >> SHADOW_SCALE) + PAGE_OFFSET + SHADOW_OFFSET;
}

struct shadow_segment_endpoint {
        u8 *chunk;
        s8 offset;  // in [0, SHADOW_GRANULARITY)
        s8 value;  // = *chunk
};

static void init_shadow_segment_endpoint(struct shadow_segment_endpoint *endp,
                                         uptr addr)
{
        CHECK(endp != NULL);
        endp->chunk = (u8*)mem_to_shadow(addr);
        CHECK(endp->chunk != NULL);
        endp->offset = addr & (SHADOW_GRANULARITY - 1);
        endp->value = *endp->chunk;
}

void asan_init_shadow(void)
{
        uptr shadow_size = (max_pfn * PAGE_SIZE) >> SHADOW_SCALE;
        memblock_reserve(SHADOW_OFFSET, shadow_size);
        printk(KERN_ERR "Shadow memory size: %lu\n", shadow_size);
}

void asan_poison(void *addr, uptr size)
{
        struct shadow_segment_endpoint beg, end;
        s8 value;

        if (size == 0) return;

        init_shadow_segment_endpoint(&beg, (uptr)addr);
        init_shadow_segment_endpoint(&end, (uptr)addr + size);

        if (beg.chunk == end.chunk) {
                CHECK(beg.offset < end.offset);
                CHECK(beg.value == end.value);
                value = beg.value;
                if (value > 0 && value <= end.offset) {
                        if (beg.offset > 0) {
                                *beg.chunk = min(value, beg.offset);
                        } else {
                                *beg.chunk = ASAN_POISONED_MEMORY;
                        }
                }
                return;
        }

        CHECK(beg.chunk < end.chunk);
        if (beg.offset > 0) {
                if (beg.value == 0) {
                        *beg.chunk = beg.offset;
                } else {
                        *beg.chunk = min(beg.value, beg.offset);
                }
                beg.chunk++;
        }
        memset(beg.chunk, ASAN_POISONED_MEMORY, end.chunk - beg.chunk);
        if (end.value > 0 && end.value <= end.offset) {
                *end.chunk = ASAN_POISONED_MEMORY;
        }
}

void asan_unpoison(void *addr, uptr size)
{
        struct shadow_segment_endpoint beg, end;
        s8 value;

        if (size == 0) return;

        init_shadow_segment_endpoint(&beg, (uptr)addr);
        init_shadow_segment_endpoint(&end, (uptr)addr + size);

        if (beg.chunk == end.chunk) {
                CHECK(beg.offset < end.offset);
                CHECK(beg.value == end.value);
                value = beg.value;
                if (value != 0) {
                        *beg.chunk = max(value, end.offset);
                }
                return;
        }
        
        CHECK(beg.chunk < end.chunk);
        if (beg.offset > 0) {
                *beg.chunk = 0;
                beg.chunk++;
        }
        memset(beg.chunk, 0, end.chunk - beg.chunk);
        if (end.offset > 0 && end.value != 0) {
                *end.chunk = max(end.value, end.offset);
        }
}

static int asan_is_poisoned(uptr addr)
{
        const uptr ACCESS_SIZE = 1;
        u8* shadow_addr = (u8*)mem_to_shadow(addr);
        s8 shadow_value = *shadow_addr;
        if (shadow_value != 0) {
                u8 last_accessed_byte = (addr & (SHADOW_GRANULARITY - 1))
                                        + ACCESS_SIZE - 1;
                return (last_accessed_byte >= shadow_value) ? 1 : 0;
        }
        return 0;
}

void *asan_region_is_poisoned(void *addr, uptr size)
{
        uptr beg = (uptr)addr;
        uptr end = beg + size;
        uptr aligned_beg = round_up_to(beg, SHADOW_GRANULARITY);
        uptr aligned_end = round_down_to(end, SHADOW_GRANULARITY);
        uptr shadow_beg = mem_to_shadow(aligned_beg);
        uptr shadow_end = mem_to_shadow(aligned_end);
        if (asan_is_poisoned(shadow_beg) == 0 &&
            asan_is_poisoned(shadow_end) == 0 &&
            (shadow_end <= shadow_beg ||
             mem_is_zero((const u8*)shadow_beg, shadow_end - shadow_beg) == 1))
                return NULL;
        for (; beg < end; beg++)
                if(asan_is_poisoned(beg) == 1)
                        return (void*)beg;
        UNREACHABLE("mem_is_zero returned false, but poisoned byte was not found");
        return NULL;
}

static void run_tests(void)
{
        uptr i;

        printk(KERN_ERR "Running tests...\n");

        CHECK(asan_region_is_poisoned((void*)PAGE_OFFSET, 50) == NULL);

        asan_poison((void*)(PAGE_OFFSET + 5), 27);
        for (i = PAGE_OFFSET; i < PAGE_OFFSET + 5; i++) {
                CHECK(asan_is_poisoned(i) == 0);
        }
        for (i = PAGE_OFFSET + 5;
             i < round_down_to(PAGE_OFFSET + 5 + 27, SHADOW_GRANULARITY);
             i++) {
                CHECK(asan_is_poisoned(i) == 1);
                //printk(KERN_ERR "%lx %c\n", i,
                //       asan_is_poisoned(i) == 0 ? 'u' : 'p');
        }
        for (i = PAGE_OFFSET + 5 + 27; i < PAGE_OFFSET + 50; i++) {
                CHECK(asan_is_poisoned(i) == 0);
        }


        CHECK(asan_region_is_poisoned((void*)PAGE_OFFSET, 50)
              == (void*)(PAGE_OFFSET + 5)); 
        CHECK(asan_region_is_poisoned((void*)(PAGE_OFFSET + 10), 50)
              == (void*)(PAGE_OFFSET + 10));

        asan_unpoison((void*)(PAGE_OFFSET + 5), 27);
        for (i = PAGE_OFFSET; i < PAGE_OFFSET + 50; i++) {
                CHECK(asan_is_poisoned(i) == 0);
        }

        CHECK(asan_region_is_poisoned((void*)PAGE_OFFSET, 50) == NULL);

        printk(KERN_ERR "Passed all the tests.\n");
}

void asan_on_kernel_init(void)
{
        run_tests();
}
