#include "report.h"

#include <asm-generic/bug.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

#include <linux/asan.h>

#include "mapping.h"
#include "stack.h"

#define SHADOW_BYTES_PER_ROW 16

static void print_error_description(unsigned long addr)
{
	char error_type[64];
	u8 *shadow = (u8 *)mem_to_shadow(addr);

	BUG_ON(*shadow == 0);
	switch (*shadow) {
		case ASAN_HEAP_REDZONE:
			sprintf(error_type, "heap-buffer-overflow");
			break;
		case ASAN_HEAP_FREE:
			sprintf(error_type, "heap-use-after-free");
			break;
		default:
			BUG(); /* Unreachable. */
	}
 
	pr_err("ERROR: AddressSanitizer: %s on address %lx\n", error_type, addr);
}

static void print_stack_traces(unsigned long addr)
{
	asan_print_current_stack();
	/* TODO: print alloc stack
	   TODO: print free stack */
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
	u8 *current;

	for (i = 0; i < SHADOW_BYTES_PER_ROW; i++) {
		current = shadow + i;
		before = (current == guilty) ? "[" :
			(i != 0 && current - 1 == guilty) ? "" : " ";
		after = (current == guilty) ? "]" : "";
		output += print_shadow_byte(before, *current, after, output);
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
