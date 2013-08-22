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

#if ASAN_COLORED_OUTPUT_ENABLE
	#define ASAN_NORMAL  "\x1B[0m"
	#define ASAN_RED     "\x1B[1;31m"
	#define ASAN_BLUE    "\x1B[1;34m"
	#define ASAN_MAGENTA "\x1B[1;35m"
	#define ASAN_WHITE   "\x1B[1;37m"
#else
	#define ASAN_NORMAL  ""
	#define ASAN_RED     ""
	#define ASAN_BLUE     ""
	#define ASAN_MAGENTA ""
	#define ASAN_WHITE   ""
#endif

static void print_error_description(unsigned long addr)
{
	u8 *shadow = (u8 *)mem_to_shadow(addr);
	const char *bug_type = "unknown-crash";

	/* TODO: handle 16 bytes accesses. */

	switch (*shadow) {
	case 0 ... SHADOW_GRANULARITY - 1:
	case ASAN_HEAP_REDZONE:
		bug_type = "heap-buffer-overflow";
		break;
	case ASAN_HEAP_FREE:
		bug_type = "heap-use-after-free";
		break;
	}

	pr_err("%sERROR: AddressSanitizer: %s on address %lx%s\n",
	       ASAN_RED, bug_type, addr, ASAN_NORMAL);
}

static void print_stack_traces(unsigned long addr)
{
	u8 *shadow = (u8 *)mem_to_shadow(addr);
	u8 *shadow_beg, *shadow_end;
	unsigned long object_addr, object_size;
	unsigned long *alloc_stack, *free_stack;
	struct asan_redzone *redzone;

	pr_err("%sAccessed by thread T%d:%s\n", ASAN_BLUE,
	       get_current_thread_id(), ASAN_NORMAL);
	asan_print_current_stack_trace();

	if (*shadow != ASAN_HEAP_FREE)
		return;

	shadow_beg = shadow_end = shadow;
	/* FIXME: check bounds. */
	while (*(shadow_beg - 1) == ASAN_HEAP_FREE)
		shadow_beg--;
	while (*shadow_end == ASAN_HEAP_FREE)
		shadow_end++;

	object_addr = shadow_to_mem((unsigned long)shadow_beg);
	object_size = shadow_to_mem((unsigned long)shadow_end) -
		      object_addr;

	redzone = (struct asan_redzone *)(object_addr + object_size);
	alloc_stack = redzone->alloc_stack;
	free_stack = redzone->free_stack;

	pr_err("%sAllocated by thread T%d:%s\n", ASAN_MAGENTA,
	       redzone->alloc_thread_id, ASAN_NORMAL);
	asan_print_stack_trace(alloc_stack, ASAN_FRAMES_IN_STACK_TRACE);

	pr_err("%sFreed by thread T%d:%s\n", ASAN_MAGENTA,
	       redzone->free_thread_id, ASAN_NORMAL);
	asan_print_stack_trace(free_stack, ASAN_FRAMES_IN_STACK_TRACE);
}

static int print_shadow_byte(const char *before, u8 shadow,
			     const char *after, char *output)
{
	const char *color_prefix = ASAN_NORMAL;
	const char *color_postfix = ASAN_NORMAL;

	switch (shadow) {
	case 0 ... SHADOW_GRANULARITY - 1:
		color_prefix = ASAN_WHITE;
		break;
	case ASAN_HEAP_REDZONE:
		color_prefix = ASAN_RED;
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
	int j;
	char buffer[512];
	const char *prefix;
	unsigned long shadow = mem_to_shadow(addr);
	unsigned long aligned_shadow = shadow & ~(SHADOW_BYTES_PER_ROW - 1);

	pr_err("Shadow bytes around the buggy address:\n");
	for (j = -5; j <= 5; j++) {
		print_shadow_bytes((u8 *)aligned_shadow +
				   j * SHADOW_BYTES_PER_ROW,
				   (u8 *)shadow, buffer);
		prefix = (j == 0) ? "=>" : "  ";
		pr_err("%s%lx:%s\n", prefix,
			aligned_shadow + j * 0x10, buffer);
	}
}

static void print_shadow_legend(void)
{
	int i;
	char buffer[64];

	for (i = 1; i < SHADOW_GRANULARITY; i++)
		sprintf(buffer + (i - 1) * 3, "%02x ", i);

	pr_err("Shadow byte legend (one shadow byte represents %d application bytes):\n",
	       (int)SHADOW_GRANULARITY);
	pr_err("  Addressable:           %s%02x%s\n",
	       ASAN_WHITE, 0, ASAN_NORMAL);
	pr_err("  Partially addressable: %s%s%s\n",
	       ASAN_WHITE, buffer, ASAN_NORMAL);
	pr_err("  Heap redzone:          %s%02x%s\n",
	       ASAN_RED, ASAN_HEAP_REDZONE, ASAN_NORMAL);
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
	print_stack_traces(poisoned_addr);
	print_shadow_for_address(poisoned_addr);
	print_shadow_legend();
	pr_err("=========================================================================\n");
}
