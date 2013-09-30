#include "asan.h"

#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

#define SHADOW_BYTES_PER_BLOCK 8
#define SHADOW_BLOCKS_PER_ROW 4
#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
#define SHADOW_ROWS_AROUND_ADDR 5

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

int asan_error_counter; /* = 0 */
DEFINE_SPINLOCK(asan_error_counter_lock);

static void asan_print_stack_trace(unsigned long *stack, unsigned int entries)
{
	unsigned int i;
	void *frame;

	for (i = 0; i < entries; i++) {
		if (stack[i] == ULONG_MAX || stack[i] == 0)
			break;
		frame = (void *)stack[i];
		pr_err(" [<%p>] %pS\n", frame, frame);
	}
}

static void asan_print_current_stack_trace(unsigned long strip_addr)
{
	unsigned long stack[ASAN_MAX_STACK_TRACE_FRAMES];
	unsigned int entries = asan_save_stack_trace(&stack[0],
		ASAN_MAX_STACK_TRACE_FRAMES, strip_addr);
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

	pr_err("%sAddressSanitizer: %s on address %lx%s\n",
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

	pr_err("%sThe buggy address %lx is located %lu bytes %s%s\n"
	       "%s of %lu-byte region [%lx, %lx)%s\n", COLOR_GREEN, addr,
	       rel_bytes, rel_type, COLOR_NORMAL, COLOR_GREEN, object_size,
	       object_addr, object_addr + object_size, COLOR_NORMAL);
}

static struct kmem_cache *asan_mem_to_cache(const void *obj)
{
	struct page *page = virt_to_head_page(obj);
	return page->slab_cache;
}

static void asan_describe_heap_address(unsigned long addr,
				       unsigned long access_size,
				       bool is_write,
				       unsigned long strip_addr)
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
		       COLOR_BLUE, is_write ? "Write" : "Read", access_size,
		       addr, asan_current_thread_id(), COLOR_NORMAL);
		asan_print_current_stack_trace(strip_addr);
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

	pr_err("%s%s of size %lu by thread T%d:%s\n", COLOR_BLUE,
	       is_write ? "Write" : "Read", access_size,
	       asan_current_thread_id(), COLOR_NORMAL);
	asan_print_current_stack_trace(strip_addr);
	pr_err("\n");

	if (free_stack != NULL) {
		pr_err("%sFreed by thread T%d:%s\n", COLOR_MAGENTA,
		       redzone->free_thread_id, COLOR_NORMAL);
		asan_print_stack_trace(free_stack, ASAN_STACK_TRACE_FRAMES);
		pr_err("\n");
	}

	if (alloc_stack != NULL) {
		pr_err("%sAllocated by thread T%d:%s\n", COLOR_MAGENTA,
		       redzone->alloc_thread_id, COLOR_NORMAL);
		asan_print_stack_trace(alloc_stack, ASAN_STACK_TRACE_FRAMES);
		pr_err("\n");
	}

	asan_describe_access_to_heap(addr, object_addr, object_size,
				     redzone->kmalloc_size);
	pr_err("\n");
}

static char *asan_print_shadow_byte(const char *before, u8 shadow,
				    const char *after, char *output)
{
	const char *color_prefix = COLOR_NORMAL;
	const char *color_postfix = COLOR_NORMAL;
	char marker = 'X';

	switch (shadow) {
	case ASAN_HEAP_REDZONE:
		color_prefix = COLOR_RED;
		marker = 'r';
		break;
	case ASAN_HEAP_KMALLOC_REDZONE:
		color_prefix = COLOR_YELLOW;
		marker = 'r';
		break;
	case 0:
		color_prefix = COLOR_WHITE;
		marker = '.';
		break;
	case 1 ... ASAN_SHADOW_GRANULARITY - 1:
		color_prefix = COLOR_WHITE;
		marker = '0' + shadow;
		break;
	case ASAN_HEAP_FREE:
		color_prefix = COLOR_MAGENTA;
		marker = 'f';
		break;
	case ASAN_SHADOW_GAP:
		color_prefix = COLOR_BLUE;
		marker = 'g';
		break;
	}

	sprintf(output, "%s%s%c%s%s", before, color_prefix,
		marker, color_postfix, after);
	return output + strlen(before) + strlen(color_prefix)
		+ 1 + strlen(color_postfix) + strlen(after);
}

static char *asan_print_shadow_block(u8 *shadow, u8 *guilty, char *output)
{
	int i;
	const char *before, *after;

	for (i = 0; i < SHADOW_BYTES_PER_BLOCK; i++) {
		before = (shadow == guilty) ? ">" : "";
		after = (shadow == guilty) ? "<" : "";
		output = asan_print_shadow_byte(before, *shadow,
						after, output);
		shadow++;
	}

	return output;
}

static bool asan_block_guilty(u8 *block, u8 *guilty)
{
	return (block <= guilty) && (guilty < block + SHADOW_BYTES_PER_BLOCK);
}

static void asan_print_shadow_row(u8 *shadow, u8 *guilty, char *output)
{
	int i;
	const char *before;
	bool curr_guilty;
	bool prev_guilty;

	for (i = 0; i < SHADOW_BLOCKS_PER_ROW; i++) {
		curr_guilty = asan_block_guilty(shadow, guilty);
		prev_guilty = asan_block_guilty(shadow - SHADOW_BYTES_PER_BLOCK,
						guilty);
		before = curr_guilty ? " " :
			 (prev_guilty && i != 0 ? " " : "  ");
		sprintf(output, before);
		output += strlen(before);
		output = asan_print_shadow_block(shadow, guilty, output);
		shadow += SHADOW_BYTES_PER_BLOCK;
	}
}

static void asan_print_shadow_for_address(unsigned long addr)
{
	int i;
	char buffer[512];
	unsigned long shadow = asan_mem_to_shadow(addr);
	unsigned long aligned_shadow = round_down(shadow, SHADOW_BYTES_PER_ROW)
		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;

	pr_err("Memory state around the buggy address:\n");

	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
		asan_print_shadow_row((u8 *)aligned_shadow,
				      (u8 *)shadow, buffer);
		pr_err("%s%lx:%s\n", (i == 0) ? ">" : " ",
		       asan_shadow_to_mem(aligned_shadow), buffer);
		aligned_shadow += SHADOW_BYTES_PER_ROW;
	}
}

static void asan_print_shadow_legend(void)
{
	int i;
	char partially_addressable[64];

	for (i = 1; i < ASAN_SHADOW_GRANULARITY; i++)
		sprintf(partially_addressable + (i - 1) * 3, "%02x ", i);

	pr_err("Legend:\n");
	pr_err(" %s.%s - 8 allocated bytes\n", COLOR_WHITE, COLOR_NORMAL);
	pr_err(" %sf%s - freed bytes\n", COLOR_MAGENTA, COLOR_NORMAL);
	pr_err(" %sr%s - redzone bytes\n", COLOR_RED, COLOR_NORMAL);
	pr_err(" x=%s1%s..%s7%s - x allocated bytes + (8-x) redzone bytes\n",
	       COLOR_WHITE, COLOR_NORMAL, COLOR_WHITE, COLOR_NORMAL);
}

void asan_report_error(unsigned long poisoned_addr, unsigned long access_size,
		       bool is_write, unsigned long strip_addr)
{
	unsigned long flags;

	spin_lock_irqsave(&asan_error_counter_lock, flags);
	asan_error_counter++;
	if (asan_error_counter > 100)
		return;
	spin_unlock_irqrestore(&asan_error_counter_lock, flags);

	pr_err("=========================================================================\n");
	asan_print_error_description(poisoned_addr, access_size);
	asan_describe_heap_address(poisoned_addr, access_size,
				   is_write, strip_addr);
	asan_print_shadow_for_address(poisoned_addr);
	asan_print_shadow_legend();
	pr_err("=========================================================================\n");
}
