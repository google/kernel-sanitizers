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

	pr_err("ERROR: AddressSanitizer: %s on address %lx\n", bug_type, addr);
}

static void print_stack_traces(unsigned long addr)
{
	u8 *shadow = (u8 *)mem_to_shadow(addr);
	u8 *shadow_beg, *shadow_end;
	unsigned long object_addr, object_size;
	unsigned long *alloc_stack, *free_stack;
	struct asan_redzone *redzone;

	pr_err("Accessed by thread #%d:\n", get_current_thread_id());
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

	pr_err("Allocated by thread #%d:\n", redzone->alloc_thread_id);
	asan_print_stack_trace(alloc_stack, ASAN_FRAMES_IN_STACK_TRACE);

	pr_err("Freed by thread #%d:\n", redzone->free_thread_id);
	asan_print_stack_trace(free_stack, ASAN_FRAMES_IN_STACK_TRACE);
}

static int print_shadow_byte(const char *before, u8 shadow,
			     const char *after, char *output)
{
	sprintf(output, "%s%02x%s", before, shadow, after);
	return strlen(before) + 2 + strlen(after);
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
	char buffer[64];
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
	pr_err("  Addressable:           %02x\n", 0);
	pr_err("  Partially addressable: %s\n", buffer);
	pr_err("  Heap redzone:          %02x\n", ASAN_HEAP_REDZONE);
	pr_err("  Freed heap region:     %02x\n", ASAN_HEAP_FREE);
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
