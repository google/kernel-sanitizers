#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "internal.h"

void do_bo(void)
{
	char *ptr;
	pr_err("Trying buffer-overflow...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 33) = 'x';
	kfree(ptr);
}

void do_bo_kmalloc(void)
{
	char *ptr;
	pr_err("Trying buffer-overflow in kmalloc...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 18) = 'x';
	kfree(ptr);
}

void do_bo_krealloc(void)
{
	char* ptr;
	pr_err("Trying buffer-overflow after krealloc...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	ptr = krealloc(ptr, 19, GFP_KERNEL);
	ptr[20] = 'x';
	kfree(ptr);
}

void do_bo_left(void)
{
	char *ptr;
	pr_err("Trying buffer-overflow to the left...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr - 1) = 'x';
	kfree(ptr);
}

void do_uaf(void)
{
	char *ptr;
	pr_err("Trying use-after-free...\n");
	ptr = kmalloc(128, GFP_KERNEL);
	kfree(ptr);
	*(ptr + 126 - 64) = 'x';
}

void do_uaf_memset(void)
{
	char *ptr;
	pr_err("Trying use-after-free in memset...\n");
	ptr = kmalloc(33, GFP_KERNEL);
	kfree(ptr);
	memset(ptr, 0, 30);
}

void do_uaf_quarantine(void)
{
	char *ptr1, *ptr2;
	pr_err("Trying use-after-free in quarantine...\n");
	ptr1 = kmalloc(ASAN_QUARANTINE_SIZE, GFP_KERNEL);
	if (ptr1 == NULL) {
		pr_err("Quarantine is too big, kmalloc failed.\n");
		return;
	}
	kfree(ptr1);
	ptr2 = kmalloc(ASAN_QUARANTINE_SIZE, GFP_KERNEL);
	ptr1[0] = 'x';
	kfree(ptr2);
}
