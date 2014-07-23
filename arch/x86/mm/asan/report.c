#include "asan.h"

#include <linux/fs_struct.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>

/* Shadow layout customization. */
#define SHADOW_BYTES_PER_BLOCK 8
#define SHADOW_BLOCKS_PER_ROW 4
#define SHADOW_BYTES_PER_ROW (SHADOW_BLOCKS_PER_ROW * SHADOW_BYTES_PER_BLOCK)
#define SHADOW_ROWS_AROUND_ADDR 5

#define MAX_OBJECT_SIZE (2UL << 20)
#define MAX_FUNCTION_NAME_SIZE (128)

#if ASAN_COLORED_OUTPUT_ENABLE
	#define COLOR(x) (x)
#else
	#define COLOR(x) ""
#endif

#define COLOR_NORMAL  COLOR("\x1B[0m")
#define COLOR_RED     COLOR("\x1B[1;31m")
#define COLOR_GREEN   COLOR("\x1B[1;32m")
#define COLOR_YELLOW  COLOR("\x1B[1;33m")
#define COLOR_BLUE    COLOR("\x1B[1;34m")
#define COLOR_MAGENTA COLOR("\x1B[1;35m")
#define COLOR_WHITE   COLOR("\x1B[1;37m")

static void print_compressed_stack_trace(unsigned int *stack,
					 unsigned int entries)
{
	unsigned int i;
	unsigned long frame;

	for (i = 0; i < entries; i++) {
		if (stack[i] == UINT_MAX || stack[i] == 0)
			break;
		frame = (ULONG_MAX - UINT_MAX) | stack[i];
		pr_err(" [<%p>] %pS\n", (void *)frame, (void *)frame);
	}
}

static void print_current_stack_trace(unsigned long strip_addr)
{
	unsigned int stack[ASAN_MAX_STACK_TRACE_FRAMES];
	unsigned int entries = asan_compress_and_save_stack_trace(&stack[0],
		ASAN_MAX_STACK_TRACE_FRAMES, strip_addr);
	print_compressed_stack_trace(&stack[0], entries);
}

static void print_error_description(struct access_info *info)
{
	u8 *shadow = (u8 *)asan_mem_to_shadow(info->poisoned_addr);
	const char *bug_type = "unknown-crash";
	char function[MAX_FUNCTION_NAME_SIZE];
	int i;

	/* If we are accessing 16 bytes, look at the second shadow byte. */
	if (*shadow == 0 && info->access_size > ASAN_SHADOW_GRAIN)
		shadow++;

	switch (*shadow) {
	case ASAN_HEAP_REDZONE:
	case ASAN_HEAP_KMALLOC_REDZONE:
	case 0 ... ASAN_SHADOW_GRAIN - 1:
		bug_type = "heap-buffer-overflow";
		break;
	case ASAN_HEAP_FREE:
		bug_type = "heap-use-after-free";
		break;
	case ASAN_SHADOW_GAP:
		bug_type = "wild-memory-access";
		break;
	}

	sprintf(function, "%pS", (void *)info->strip_addr);
	for (i = 0; i < MAX_FUNCTION_NAME_SIZE; i++) {
		if (function[i] == '+') {
			function[i] = '\0';
			break;
		}
	}

	pr_err("%sAddressSanitizer: %s in %s%s\n",
	       COLOR_RED, bug_type, function, COLOR_NORMAL);
}

static void print_memory_block_description(unsigned long addr,
					   unsigned long object_addr,
					   size_t object_size,
					   size_t kmalloc_size)
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

static void print_address_description(struct access_info *info)
{
	void *poisoned_ptr = (void *)info->poisoned_addr;
	u8 *shadow = (u8 *)asan_mem_to_shadow(info->poisoned_addr);
	bool use_after_free = (*shadow == ASAN_HEAP_FREE);

	struct redzone *redzone;
	unsigned int *alloc_stack = NULL;
	unsigned int *free_stack = NULL;

	struct page *page = virt_to_head_page(poisoned_ptr);
	struct kmem_cache *cache = page->slab_cache;
	size_t object_size = cache->object_size;
	void *object;
	unsigned long object_addr;
	u32 offset, idx;

	if (!PageSlab(page) || !ASAN_HAS_REDZONE(cache) || *shadow == ASAN_SHADOW_GAP) {
		pr_err("%s%s of size %lu by thread T%d:%s\n",
		       COLOR_BLUE, info->is_write ? "Write" : "Read",
		       info->access_size, info->thread_id, COLOR_NORMAL);
		print_current_stack_trace(info->strip_addr);
		pr_err("\n");
		pr_err("%sNo metainfo is available for this access.%s\n",
		       COLOR_BLUE, COLOR_NORMAL);
		pr_err("\n");
		return;
	}

	offset = poisoned_ptr - page->s_mem;
	idx = reciprocal_divide(offset, cache->reciprocal_buffer_size);
	object = page->s_mem + cache->size * idx;
	object_addr = (unsigned long)object;
	redzone = (struct redzone *)(object + object_size);

	alloc_stack = redzone->alloc_stack;
	if (use_after_free)
		free_stack = redzone->free_stack;

	pr_err("%s%s of size %lu by thread T%d:%s\n",
	       COLOR_BLUE, info->is_write ? "Write" : "Read",
	       info->access_size, info->thread_id, COLOR_NORMAL);
	print_current_stack_trace(info->strip_addr);
	pr_err("\n");

	if (free_stack != NULL) {
		pr_err("%sFreed by thread T%d:%s\n", COLOR_MAGENTA,
		       redzone->free_thread_id, COLOR_NORMAL);
		print_compressed_stack_trace(free_stack,
			ASAN_STACK_TRACE_FRAMES);
		pr_err("\n");
	}

	if (alloc_stack != NULL) {
		pr_err("%sAllocated by thread T%d:%s\n", COLOR_MAGENTA,
		       redzone->alloc_thread_id, COLOR_NORMAL);
		print_compressed_stack_trace(alloc_stack,
			ASAN_STACK_TRACE_FRAMES);
		pr_err("\n");
	}

	print_memory_block_description(info->poisoned_addr, object_addr,
				       object_size, redzone->kmalloc_size);
	pr_err("\n");
}

static char *print_shadow_byte(u8 shadow, char *output)
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
	case 1 ... ASAN_SHADOW_GRAIN - 1:
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

	sprintf(output, "%s%c%s", color_prefix, marker, color_postfix);
	return output + strlen(color_prefix) + 1 + strlen(color_postfix);
}

static char *print_shadow_block(u8 *shadow, u8 *guilty, char *output)
{
	int i;

	for (i = 0; i < SHADOW_BYTES_PER_BLOCK; i++) {
		output = print_shadow_byte(*shadow, output);
		shadow++;
	}

	return output;
}

static void print_shadow_row(u8 *row, u8 *guilty, char *output)
{
	int i;
	const char *before;

	for (i = 0; i < SHADOW_BLOCKS_PER_ROW; i++) {
		before = (i == 0) ? "" : " ";
		sprintf(output, before);
		output += strlen(before);
		output = print_shadow_block(row, guilty, output);
		row += SHADOW_BYTES_PER_BLOCK;
	}
}

static bool row_is_guilty(unsigned long row, unsigned long guilty)
{
	return (row <= guilty) && (guilty < row + SHADOW_BYTES_PER_ROW);
}

static void print_shadow_pointer(unsigned long row, unsigned long shadow,
				 char *output)
{
	/* The length of ">ff00ff00ff00ff00: " is 19 chars. */
	unsigned long space_count = 19 + shadow - row +
		(shadow - row) / SHADOW_BYTES_PER_BLOCK;
	unsigned long i;

	for (i = 0; i < space_count; i++)
		output[i] = ' ';
	output[space_count] = '^';
	output[space_count + 1] = '\0';
}

static void print_shadow_for_address(unsigned long addr)
{
	int i;
	char buffer[512];
	unsigned long shadow = asan_mem_to_shadow(addr);
	unsigned long aligned_shadow = round_down(shadow, SHADOW_BYTES_PER_ROW)
		- SHADOW_ROWS_AROUND_ADDR * SHADOW_BYTES_PER_ROW;

	pr_err("Memory state around the buggy address:\n");

	for (i = -SHADOW_ROWS_AROUND_ADDR; i <= SHADOW_ROWS_AROUND_ADDR; i++) {
		print_shadow_row((u8 *)aligned_shadow, (u8 *)shadow, buffer);
		pr_err("%s%lx: %s\n", (i == 0) ? ">" : " ",
		       asan_shadow_to_mem(aligned_shadow), buffer);
		if (row_is_guilty(aligned_shadow, shadow)) {
			print_shadow_pointer(aligned_shadow, shadow, buffer);
			pr_err("%s\n", buffer);
		}
		aligned_shadow += SHADOW_BYTES_PER_ROW;
	}
}

static void print_shadow_legend(void)
{
	int i;
	char partially_addressable[64];

	for (i = 1; i < ASAN_SHADOW_GRAIN; i++)
		sprintf(partially_addressable + (i - 1) * 3, "%02x ", i);

	pr_err("Legend:\n");
	pr_err(" %sf%s - 8 freed bytes\n", COLOR_MAGENTA, COLOR_NORMAL);
	pr_err(" %sr%s - 8 redzone bytes\n", COLOR_RED, COLOR_NORMAL);
	pr_err(" %s.%s - 8 allocated bytes\n", COLOR_WHITE, COLOR_NORMAL);
	pr_err(" x=%s1%s..%s7%s - x allocated bytes + (8-x) redzone bytes\n",
	       COLOR_WHITE, COLOR_NORMAL, COLOR_WHITE, COLOR_NORMAL);
}

void asan_report_error(struct access_info *info)
{
	unsigned long flags;

	spin_lock_irqsave(&asan_error_counter_lock, flags);
	asan_error_counter++;
	if (asan_error_counter > 100)
		return;
	spin_unlock_irqrestore(&asan_error_counter_lock, flags);

	pr_err("==================================================================\n");
	print_error_description(info);
	print_address_description(info);
	print_shadow_for_address(info->poisoned_addr);
	print_shadow_legend();
	pr_err("==================================================================\n");
}

void asan_report_user_access(struct access_info *info)
{
	unsigned long flags;

	spin_lock_irqsave(&asan_error_counter_lock, flags);
	asan_error_counter++;
	if (asan_error_counter > 100)
		return;
	spin_unlock_irqrestore(&asan_error_counter_lock, flags);

	pr_err("==================================================================\n");
	pr_err("%sAddressSanitizer: user-memory-access on address %lx%s\n",
	       COLOR_RED, info->poisoned_addr, COLOR_NORMAL);
	pr_err("%s%s of size %lu by thread T%d:%s\n",
	       COLOR_BLUE, info->is_write ? "Write" : "Read",
	       info->access_size, info->thread_id, COLOR_NORMAL);
	print_current_stack_trace(info->strip_addr);
	pr_err("==================================================================\n");
}
