#include "asan.h"

#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

#define SHADOW_BYTES_PER_ROW 16
#define MAX_OBJECT_SIZE (2 << 20)

#if ASAN_COLORED_OUTPUT_ENABLE
	#define COLOR_NORMAL  "\x1B[0m"
	#define COLOR_RED     "\x1B[1;31m"
	#define COLOR_GREEN   "\x1B[1;32m"
	#define COLOR_YELLOW  "\x1B[1;33m"
	#define COLOR_BLUE    "\x1B[1;34m"
	#define COLOR_MAGENTA "\x1B[1;35m"
	#define COLOR_WHITE   "\x1B[1;37m"
#else
	#define COLOR_NORMAL  ""
	#define COLOR_RED     ""
	#define COLOR_GREEN   ""
	#define COLOR_YELLOW  ""
	#define COLOR_BLUE    ""
	#define COLOR_MAGENTA ""
	#define COLOR_WHITE   ""
#endif

static void asan_print_stack_trace(unsigned long *stack, unsigned int max_entries)
{
	unsigned int i;
	void *frame;

	for (i = 0; i < max_entries; i++) {
		if (stack[i] == ULONG_MAX || stack[i] == 0)
			break;
		frame = (void *)stack[i];
		pr_err("  #%u %p (%pS)\n", i, frame, frame);
	}
}

static void asan_print_current_stack_trace(void)
{
	unsigned long stack[ASAN_MAX_STACK_TRACE_FRAMES];
	unsigned int entries =
		asan_save_stack_trace(&stack[0], ASAN_MAX_STACK_TRACE_FRAMES);
	asan_print_stack_trace(&stack[0], entries);
}

static void asan_print_error_description(unsigned long addr,
					 unsigned long access_size)
{
	u8 *shadow = (u8 *)asan_mem_to_shadow(addr);
	const char *bug_type = "unknown-crash";

	/* If we are accessing 16 bytes, look at the second shadow byte. */
	if (*shadow == 0 && access_size > ASAN_SHADOW_GRANULARITY)
		shadow++;

	switch (*shadow) {
	case ASAN_HEAP_REDZONE:
	case ASAN_HEAP_KMALLOC_REDZONE:
	case 0 ... ASAN_SHADOW_GRANULARITY - 1:
		bug_type = "heap-buffer-overflow";
		break;
	case ASAN_HEAP_FREE:
		bug_type = "heap-use-after-free";
		break;
	case ASAN_SHADOW_GAP:
		bug_type = "wild-memory-access";
		break;
	}

	pr_err("%sERROR: AddressSanitizer: %s on address %lx%s\n",
	       COLOR_RED, bug_type, addr, COLOR_NORMAL);
}

static void asan_describe_access_to_heap(unsigned long addr,
					 unsigned long object_addr,
					 unsigned long object_size,
					 unsigned long kmalloc_size)
{
	const char *rel_type;
	unsigned long rel_bytes;

	if (object_addr == 0 || object_size == 0)
		return;

	/* XXX: describe kmalloc memory block separately? */
	if (kmalloc_size != 0)
		object_size = kmalloc_size;

	if (addr >= object_addr && addr < object_addr + object_size) {
		rel_type = "inside";
		rel_bytes = addr - object_addr;
	} else if (addr < object_addr) {
		rel_type = "to the left";
		rel_bytes = object_addr - addr;
	} else if (addr >= object_addr + object_size) {
		rel_type = "to the right";
		rel_bytes = addr - (object_addr + object_size);
	} else {
		BUG(); /* Unreachable. */
	}

	pr_err("%s%lx is located %lu bytes %s of %lu-byte region [%lx, %lx)%s\n",
	       COLOR_GREEN, addr, rel_bytes, rel_type, object_size, object_addr,
	       object_addr + object_size, COLOR_NORMAL);
}

static struct kmem_cache *asan_mem_to_cache(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page->slab_cache;
}

static void asan_describe_heap_address(unsigned long addr,
				       unsigned long access_size,
				       bool is_write)
{
	u8 *shadow = (u8 *)asan_mem_to_shadow(addr);
	u8 *shadow_left, *shadow_right;
	unsigned long redzone_addr;
	struct asan_redzone *redzone;
	bool use_after_free = (*shadow == ASAN_HEAP_FREE);

	unsigned long object_addr = 0;
	unsigned long object_size = 0;
	unsigned long *alloc_stack = NULL;
	unsigned long *free_stack = NULL;

	struct kmem_cache *cache = asan_mem_to_cache((void *)addr);

	if (!cache->asan_has_redzone || *shadow == ASAN_SHADOW_GAP) {
		pr_err("%s%s of size %lu at %lx thread T%d:%s\n",
		       COLOR_BLUE, is_write ? "WRITE" : "READ", access_size,
		       addr, asan_get_current_thread_id(), COLOR_NORMAL);
		asan_print_current_stack_trace();
		pr_err("\n");
		pr_err("%sNo metainfo is available for this access.%s\n",
		       COLOR_BLUE, COLOR_NORMAL);
		pr_err("\n");
		return;
	}

	switch (*shadow) {
	case ASAN_HEAP_REDZONE:
		shadow_left = shadow_right = shadow;
		while (*(shadow_left - 1) == ASAN_HEAP_REDZONE)
			shadow_left--;
		while (*shadow_right == ASAN_HEAP_REDZONE)
			shadow_right++;

		if (shadow - shadow_left <= shadow_right - shadow) {
			shadow = shadow_left;
			break;
		}

		/*
		 * FIXME: we can end up in the next page, which is not
		 * allocated or it's cache has no redzone.
		 */
		shadow = shadow_right;
		while (*shadow != ASAN_HEAP_REDZONE) {
			shadow++;
			if (shadow == shadow_right + MAX_OBJECT_SIZE) {
				shadow = shadow_left;
				break;
			}
		}

		break;
	case ASAN_HEAP_KMALLOC_REDZONE:
	case 0 ... ASAN_SHADOW_GRANULARITY - 1:
		while (*shadow != ASAN_HEAP_REDZONE)
			shadow++;
		break;
	case ASAN_HEAP_FREE:
		while (*shadow == ASAN_HEAP_FREE)
			shadow++;
		break;
	}

	/* shadow now points to the beginning of the redzone. */
	redzone_addr = asan_shadow_to_mem((unsigned long)shadow);
	redzone = (struct asan_redzone *)redzone_addr;

	object_addr = (unsigned long)redzone->chunk.object;

	/*
	 * XXX: Checking for NULL is a temporary workaround for
	 * false positives in slab allocator in debug build.
	 */
	if (redzone->chunk.cache != NULL)
		object_size = redzone->chunk.cache->object_size;

	alloc_stack = redzone->alloc_stack;
	if (use_after_free)
		free_stack = redzone->free_stack;

	asan_describe_access_to_heap(addr, object_addr, object_size,
				     redzone->kmalloc_size);

	pr_err("%s%s of size %lu at %lx by thread T%d:%s\n",
	       COLOR_BLUE, is_write ? "WRITE" : "READ", access_size,
	       addr, asan_get_current_thread_id(), COLOR_NORMAL);
	asan_print_current_stack_trace();
	pr_err("\n");

	if (free_stack != NULL) {
		pr_err("%sfreed by thread T%d here:%s\n", COLOR_MAGENTA,
		       redzone->free_thread_id, COLOR_NORMAL);
		asan_print_stack_trace(free_stack, ASAN_STACK_TRACE_FRAMES);
		pr_err("\n");
	}

	if (alloc_stack != NULL) {
		pr_err("%s%sallocated by thread T%d here:%s\n", COLOR_MAGENTA,
		       free_stack == NULL ? "" : "previously ",
		       redzone->alloc_thread_id, COLOR_NORMAL);
		asan_print_stack_trace(alloc_stack, ASAN_STACK_TRACE_FRAMES);
		pr_err("\n");
	}
}

static int asan_print_shadow_byte(const char *before, u8 shadow,
				  const char *after, char *output)
{
	const char *color_prefix = COLOR_NORMAL;
	const char *color_postfix = COLOR_NORMAL;

	switch (shadow) {
	case ASAN_HEAP_REDZONE:
		color_prefix = COLOR_RED;
		break;
	case ASAN_HEAP_KMALLOC_REDZONE:
		color_prefix = COLOR_YELLOW;
		break;
	case 0 ... ASAN_SHADOW_GRANULARITY - 1:
		color_prefix = COLOR_WHITE;
		break;
	case ASAN_HEAP_FREE:
		color_prefix = COLOR_MAGENTA;
		break;
	case ASAN_SHADOW_GAP:
		color_prefix = COLOR_BLUE;
		break;
	}

	sprintf(output, "%s%s%02x%s%s", before, color_prefix, shadow,
					color_postfix, after);
	return strlen(before) + strlen(color_prefix) + 2 +
		+ strlen(color_postfix) + strlen(after);
}

static void asan_print_shadow_bytes(u8 *shadow, u8 *guilty, char *output)
{
	int i;
	const char *before, *after;

	for (i = 0; i < SHADOW_BYTES_PER_ROW; i++) {
		before = (shadow == guilty) ? "[" :
			(i != 0 && shadow - 1 == guilty) ? "" : " ";
		after = (shadow == guilty) ? "]" : "";
		output += asan_print_shadow_byte(before, *shadow,
						 after, output);
		shadow++;
	}
}

static void asan_print_shadow_for_address(unsigned long addr)
{
	int i;
	char buffer[512];
	const char *prefix;
	unsigned long shadow = asan_mem_to_shadow(addr);
	unsigned long aligned_shadow = shadow & ~(SHADOW_BYTES_PER_ROW - 1);

	pr_err("Shadow bytes around the buggy address:\n");
	for (i = -5; i <= 5; i++) {
		asan_print_shadow_bytes((u8 *)aligned_shadow +
					i * SHADOW_BYTES_PER_ROW,
					(u8 *)shadow, buffer);
		prefix = (i == 0) ? "=>" : "  ";
		pr_err("%s%lx:%s\n", prefix,
		       asan_shadow_to_mem(aligned_shadow + i * 0x10), buffer);
	}
}

static void asan_print_shadow_legend(void)
{
	int i;
	char partially_addressable[64];

	for (i = 1; i < ASAN_SHADOW_GRANULARITY; i++)
		sprintf(partially_addressable + (i - 1) * 3, "%02x ", i);

	pr_err("Shadow byte legend (one shadow byte represents %d application bytes):\n",
	       (int)ASAN_SHADOW_GRANULARITY);
	pr_err("  Addressable:           %s%02x%s\n",
	       COLOR_WHITE, 0, COLOR_NORMAL);
	pr_err("  Partially addressable: %s%s%s\n",
	       COLOR_WHITE, partially_addressable, COLOR_NORMAL);
	pr_err("  Heap redzone:          %s%02x%s\n",
	       COLOR_RED, ASAN_HEAP_REDZONE, COLOR_NORMAL);
	pr_err("  Heap kmalloc redzone:  %s%02x%s\n",
	       COLOR_YELLOW, ASAN_HEAP_KMALLOC_REDZONE, COLOR_NORMAL);
	pr_err("  Freed heap region:     %s%02x%s\n",
	       COLOR_MAGENTA, ASAN_HEAP_FREE, COLOR_NORMAL);
	pr_err("  Shadow gap:            %s%02x%s\n",
	       COLOR_BLUE, ASAN_SHADOW_GAP, COLOR_NORMAL);
}

static int counter; /* = 0 */

void asan_report_error(unsigned long poisoned_addr,
		       unsigned long access_size, bool is_write)
{
	counter++;
	if (counter > 100)
		return;

	pr_err("=========================================================================\n");
	asan_print_error_description(poisoned_addr, access_size);
	asan_describe_heap_address(poisoned_addr, access_size, is_write);
	asan_print_shadow_for_address(poisoned_addr);
	asan_print_shadow_legend();
	pr_err("=========================================================================\n");
}
