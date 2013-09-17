#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

void asan_do_bo(void)
{
	char *ptr;

	pr_err("Trying buffer-overflow...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 33) = 'x';
	kfree(ptr);
}

void asan_do_bo_kmalloc(void)
{
	char *ptr;

	pr_err("Trying buffer-overflow in kmalloc redzone...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 18) = 'x';
	kfree(ptr);
}

void asan_do_bo_krealloc(void)
{
	char *ptr1, *ptr2;

	pr_err("Trying buffer-overflow after krealloc...\n");
	ptr1 = kmalloc(17, GFP_KERNEL);
	ptr2 = krealloc(ptr1, 19, GFP_KERNEL);
	ptr2[20] = 'x';
	kfree(ptr2);
}

void asan_do_bo_krealloc_less(void)
{
	char *ptr1, *ptr2;

	pr_err("Trying buffer-overflow after krealloc...\n");
	ptr1 = kmalloc(17, GFP_KERNEL);
	ptr2 = krealloc(ptr1, 15, GFP_KERNEL);
	ptr2[16] = 'x';
	kfree(ptr2);
}

void asan_do_krealloc_more(void)
{
	char *ptr1, *ptr2;

	pr_err("Trying to access addressable memory after krealloc...\n");
	ptr1 = kmalloc(17, GFP_KERNEL);
	ptr2 = krealloc(ptr1, 19, GFP_KERNEL);
	ptr2[18] = 'x';
	kfree(ptr2);
}

void asan_do_bo_left(void)
{
	char *ptr;

	pr_err("Trying buffer-overflow to the left...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr - 1) = 'x';
	kfree(ptr);
}

void asan_do_bo_16(void)
{
	struct {
		unsigned long words[2];
	} *ptr1, *ptr2;

	pr_err("Trying buffer-overflow for 16 bytes access...\n");
	ptr1 = kmalloc(10, GFP_KERNEL);
	ptr2 = kmalloc(16, GFP_KERNEL);
	*ptr1 = *ptr2;
	kfree(ptr1);
	kfree(ptr2);
}

void asan_do_bo_4mb(void)
{
	char *ptr;

	pr_err("Trying buffer-overflow in 4mb cache...\n");
	ptr = kmalloc((4 << 20) - 8 * 16 * 5, GFP_KERNEL);
	ptr[0] = ptr[(4 << 20) - 1];
}

void asan_do_uaf(void)
{
	char *ptr;

	pr_err("Trying use-after-free...\n");
	ptr = kmalloc(128, GFP_KERNEL);
	kfree(ptr);
	*(ptr + 126 - 64) = 'x';
}

void asan_do_uaf_memset(void)
{
	char *ptr;

	pr_err("Trying use-after-free in memset...\n");
	ptr = kmalloc(33, GFP_KERNEL);
	kfree(ptr);
	memset(ptr, 0, 30);
}

void asan_do_uaf_quarantine(void)
{
	char *ptr1, *ptr2;

	pr_err("Trying use-after-free in quarantine...\n");
	ptr1 = kmalloc(42, GFP_KERNEL);
	kfree(ptr1);
	ptr2 = kmalloc(42, GFP_KERNEL);
	ptr1[5] = 'x';
	kfree(ptr2);
}
