// SPDX-License-Identifier: GPL-2.0

#include <linux/kernel.h>
#include <linux/stacktrace.h>
#include <linux/string.h>

#include "kfence.h"

#define NUM_STACK_ENTRIES 64

bool stack_entry_matches(unsigned long addr, const char *pattern)
{
	char buf[64];
	int buf_len, len;

	buf_len = scnprintf(buf, sizeof(buf), "%ps", (void *)addr);
	len = strlen(pattern);
	if (len > buf_len)
		return false;
	if (strnstr(buf, pattern, len))
		return true;
	return false;
}

static int scroll_stack_to(const unsigned long stack_entries[], int num_entries,
			   const char *pattern)
{
	int i;

	for (i = 0; i < num_entries; i++) {
		if (stack_entry_matches(stack_entries[i], pattern))
			return (i + 1 < num_entries) ? (i + 1) : 0;
	}
	return 0;
}

static int get_stack_skipnr(const unsigned long stack_entries[],
			    int num_entries, enum kfence_error_type type)
{
	switch (type) {
	case KFENCE_ERROR_UAF:
	case KFENCE_ERROR_OOB:
		return scroll_stack_to(stack_entries, num_entries,
				       "asm_exc_page_fault");
	case KFENCE_ERROR_CORRUPTION:
		return scroll_stack_to(stack_entries, num_entries,
				       "__slab_free");
	}
	return 0;
}

static int kfence_dump_stack(char *buf, size_t buf_size,
			     struct kfence_alloc_metadata *obj, bool is_alloc)
{
	unsigned long *entries;
	unsigned long nr_entries;
	depot_stack_handle_t handle;
	int len = 0;

	if (is_alloc)
		handle = obj->alloc_stack;
	else
		handle = obj->free_stack;
	if (handle) {
		nr_entries = stack_depot_fetch(handle, &entries);
		len += stack_trace_snprint(buf + len, buf_size - len, entries,
					   nr_entries, 0);
	} else {
		len += scnprintf(buf + len, buf_size - len, "  no %s stack.\n",
				 is_alloc ? "allocation" : "deallocation");
	}
	return len;
}

int kfence_dump_object(char *buf, size_t buf_size, int obj_index,
		       struct kfence_alloc_metadata *obj)
{
	int size = abs(obj->size);
	unsigned long start = obj->addr;
	struct kmem_cache *cache;
	int len = 0;

	len += scnprintf(buf + len, buf_size - len,
			 "Object #%d: starts at %px, size=%d\n", obj_index,
			 (void *)start, size);
	len += scnprintf(buf + len, buf_size - len, "allocated at:\n");
	len += kfence_dump_stack(buf + len, buf_size - len, obj, true);
	if (kfence_metadata[obj_index].state == KFENCE_OBJECT_FREED) {
		len += scnprintf(buf + len, buf_size - len, "freed at:\n");
		len += kfence_dump_stack(buf + len, buf_size - len, obj, false);
	}
	cache = kfence_metadata[obj_index].cache;
	if (cache && cache->name)
		len += scnprintf(buf + len, buf_size - len,
				 "Object #%d belongs to cache %s\n", obj_index,
				 cache->name);
	return len;
}

static void kfence_print_object(int obj_index,
				struct kfence_alloc_metadata *obj)
{
	kfence_dump_object(kfence_dump_buf, sizeof(kfence_dump_buf), obj_index,
			   obj);
	pr_err("%s", kfence_dump_buf);
}

#define BYTES_TO_DUMP 16
static void dump_bytes_at(unsigned long addr)
{
	unsigned char *c = (unsigned char *)addr;
	unsigned char *max_addr = (unsigned char *)min(ALIGN(addr, PAGE_SIZE),
						       addr + BYTES_TO_DUMP);
	char bytes[BYTES_TO_DUMP * 3 + 1];
	int len = 0;

	for (; c < max_addr; c++)
		len += scnprintf(bytes + len, sizeof(bytes) - len, "%02X ", *c);

	pr_err("Bytes at %px: %s\n", (void *)addr, bytes);
}
#undef BYTES_TO_DUMP

void kfence_report_error(unsigned long address, int obj_index,
			 struct kfence_alloc_metadata *object,
			 enum kfence_error_type type)
{
	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
	int num_stack_entries =
		stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries, type);
	bool is_left;

	pr_err("==================================================================\n");
	switch (type) {
	case KFENCE_ERROR_OOB:
		is_left = address < object->addr;
		pr_err("BUG: KFENCE: slab-out-of-bounds in %pS\n",
		       (void *)stack_entries[skipnr]);
		pr_err("Memory access at address %px to the %s of object #%d\n",
		       (void *)address, is_left ? "left" : "right", obj_index);
		break;
	case KFENCE_ERROR_UAF:
		pr_err("BUG: KFENCE: use-after-free in %pS\n",
		       (void *)stack_entries[skipnr]);
		pr_err("Memory access at address %px\n", (void *)address);
		break;
	case KFENCE_ERROR_CORRUPTION:
		pr_err("BUG: KFENCE: memory corruption in %pS\n",
		       (void *)stack_entries[skipnr]);
		pr_err("Invalid write detected at address %px\n",
		       (void *)address);
		dump_bytes_at(address);
		break;
	}

	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
			  0);
	pr_err("\n");
	kfence_print_object(obj_index, object);
	pr_err("==================================================================\n");
}
