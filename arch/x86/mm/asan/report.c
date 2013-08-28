#include "report.h"

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/types.h>

#include "internal.h"
#include "mapping.h"
#include "stack_trace.h"
#include "thread.h"

#define SHADOW_BYTES_PER_ROW 16
#define MAX_OBJECT_SIZE (2 << 20)

#if ASAN_COLORED_OUTPUT_ENABLE
	#define ASAN_NORMAL  "\x1B[0m"
	#define ASAN_RED     "\x1B[1;31m"
	#define ASAN_GREEN   "\x1B[1;32m"
	#define ASAN_YELLOW  "\x1B[1;33m"
	#define ASAN_BLUE    "\x1B[1;34m"
	#define ASAN_MAGENTA "\x1B[1;35m"
	#define ASAN_WHITE   "\x1B[1;37m"
#else
	#define ASAN_NORMAL  ""
	#define ASAN_RED     ""
	#define ASAN_GREEN   ""
	#define ASAN_YELLOW  ""
	#define ASAN_BLUE    ""
	#define ASAN_MAGENTA ""
	#define ASAN_WHITE   ""
#endif

static void print_error_description(unsigned long addr)
{
	u8 *shadow = (u8 *)mem_to_shadow(addr);
	const char *bug_type = "unknown-crash";

	/* TODO: handle 16 bytes accesses. */

	switch (*shadow) {
	case ASAN_HEAP_REDZONE:
	case ASAN_HEAP_KMALLOC_REDZONE:
	case 0 ... SHADOW_GRANULARITY - 1:
		bug_type = "heap-buffer-overflow";
		break;
	case ASAN_HEAP_FREE:
		bug_type = "heap-use-after-free";
		break;
	}

	pr_err("%sERROR: AddressSanitizer: %s on address %lx%s\n",
	       ASAN_RED, bug_type, addr, ASAN_NORMAL);
}

static void describe_access_to_heap(unsigned long addr,
				    unsigned long object_addr,
				    unsigned long object_size)
{
	const char *rel_type;
	unsigned long rel_bytes;

	if (object_addr == 0 || object_size == 0)
		return;

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
	       ASAN_GREEN, addr, rel_bytes, rel_type, object_size, object_addr,
	       object_addr + object_size, ASAN_NORMAL);
}

static void describe_heap_address(unsigned long addr)
{
	u8 *shadow = (u8 *)mem_to_shadow(addr);
	u8 *shadow_left, *shadow_right;
	unsigned long redzone_addr;
	struct asan_redzone *redzone;
	bool use_after_free = (*shadow == ASAN_HEAP_FREE);

	unsigned long object_addr = 0;
	unsigned long object_size = 0;
	unsigned long *alloc_stack = NULL;
	unsigned long *free_stack = NULL;

	switch (*shadow) {
	case ASAN_HEAP_REDZONE:
		shadow_left = shadow_right = shadow;
		while (*(shadow_left - 1) == ASAN_HEAP_REDZONE)
			shadow_left--;
		while (*shadow_right == ASAN_HEAP_REDZONE)
			shadow_right++;

		if (shadow - shadow_left <= shadow_right - shadow) {
			shadow = shadow_left;
		} else {
			shadow = shadow_right;
			while (*shadow != ASAN_HEAP_REDZONE) {
				shadow++;
				if (shadow == shadow_right + MAX_OBJECT_SIZE) {
					shadow = shadow_left;
					break;
				}
			}
		}

		break;
	case ASAN_HEAP_KMALLOC_REDZONE:
	case 0 ... SHADOW_GRANULARITY - 1:
		while (*shadow != ASAN_HEAP_REDZONE)
			shadow++;
		break;
	case ASAN_HEAP_FREE:
		while (*shadow == ASAN_HEAP_FREE)
			shadow++;
		break;
	}

	/* shadow now points to the beginning of the redzone. */
	redzone_addr = shadow_to_mem((unsigned long)shadow);
	redzone = (struct asan_redzone *)redzone_addr;

	object_addr = (unsigned long)redzone->chunk.object;
	if (redzone->chunk.cache != NULL)
		object_size = redzone->chunk.cache->object_size;

	alloc_stack = redzone->alloc_stack;
	if (use_after_free)
		free_stack = redzone->free_stack;

	describe_access_to_heap(addr, object_addr, object_size);

	pr_err("%sAccessed by thread T%d:%s\n", ASAN_BLUE,
	       get_current_thread_id(), ASAN_NORMAL);
	asan_print_current_stack_trace();
	pr_err("\n");

	if (free_stack != NULL) {
		pr_err("%sFreed by thread T%d:%s\n", ASAN_MAGENTA,
		       redzone->free_thread_id, ASAN_NORMAL);
		asan_print_stack_trace(free_stack, ASAN_FRAMES_IN_STACK_TRACE);
		pr_err("\n");
	}

	if (alloc_stack != NULL) {
		pr_err("%sAllocated by thread T%d:%s\n", ASAN_MAGENTA,
		       redzone->alloc_thread_id, ASAN_NORMAL);
		asan_print_stack_trace(alloc_stack, ASAN_FRAMES_IN_STACK_TRACE);
		pr_err("\n");
	}
}

static int print_shadow_byte(const char *before, u8 shadow,
			     const char *after, char *output)
{
	const char *color_prefix = ASAN_NORMAL;
	const char *color_postfix = ASAN_NORMAL;

	switch (shadow) {
	case ASAN_HEAP_REDZONE:
		color_prefix = ASAN_RED;
		break;
	case ASAN_HEAP_KMALLOC_REDZONE:
		color_prefix = ASAN_YELLOW;
		break;
	case 0 ... SHADOW_GRANULARITY - 1:
		color_prefix = ASAN_WHITE;
		break;
	case ASAN_HEAP_FREE:
		color_prefix = ASAN_MAGENTA;
		break;
	}

	sprintf(output, "%s%s%02x%s%s", before, color_prefix, shadow,
					color_postfix, after);
	return strlen(before) + strlen(color_prefix) + 2 +
		+ strlen(color_postfix) + strlen(after);
}

static void print_shadow_bytes(u8 *shadow, u8 *guilty, char *output)
{
	int i;
	const char *before, *after;

	for (i = 0; i < SHADOW_BYTES_PER_ROW; i++) {
		before = (shadow == guilty) ? "[" :
			(i != 0 && shadow - 1 == guilty) ? "" : " ";
		after = (shadow == guilty) ? "]" : "";
		output += print_shadow_byte(before, *shadow, after, output);
		shadow++;
	}
}

static void print_shadow_for_address(unsigned long addr)
{
	int i;
	char buffer[512];
	const char *prefix;
	unsigned long shadow = mem_to_shadow(addr);
	unsigned long aligned_shadow = shadow & ~(SHADOW_BYTES_PER_ROW - 1);

	pr_err("Shadow bytes around the buggy address:\n");
	for (i = -5; i <= 5; i++) {
		print_shadow_bytes((u8 *)aligned_shadow +
				   i * SHADOW_BYTES_PER_ROW,
				   (u8 *)shadow, buffer);
		prefix = (i == 0) ? "=>" : "  ";
		pr_err("%s%lx:%s\n", prefix,
		       shadow_to_mem(aligned_shadow + i * 0x10), buffer);
	}
}

static void print_shadow_legend(void)
{
	int i;
	char partially_addressable[64];

	for (i = 1; i < SHADOW_GRANULARITY; i++)
		sprintf(partially_addressable + (i - 1) * 3, "%02x ", i);

	pr_err("Shadow byte legend (one shadow byte represents %d application bytes):\n",
	       (int)SHADOW_GRANULARITY);
	pr_err("  Addressable:           %s%02x%s\n",
	       ASAN_WHITE, 0, ASAN_NORMAL);
	pr_err("  Partially addressable: %s%s%s\n",
	       ASAN_WHITE, partially_addressable, ASAN_NORMAL);
	pr_err("  Heap redzone:          %s%02x%s\n",
	       ASAN_RED, ASAN_HEAP_REDZONE, ASAN_NORMAL);
	pr_err("  Heap kmalloc redzone:  %s%02x%s\n",
	       ASAN_YELLOW, ASAN_HEAP_KMALLOC_REDZONE, ASAN_NORMAL);
	pr_err("  Freed heap region:     %s%02x%s\n",
	       ASAN_MAGENTA, ASAN_HEAP_FREE, ASAN_NORMAL);
}

static int counter; /* = 0 */

void asan_report_error(unsigned long poisoned_addr)
{
	counter++;
	if (counter > 100)
		return;

	pr_err("=========================================================================\n");
	print_error_description(poisoned_addr);
	describe_heap_address(poisoned_addr);
	print_shadow_for_address(poisoned_addr);
	print_shadow_legend();
	pr_err("=========================================================================\n");
}
