#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

void do_use_after_free(void)
{
	char *ptr;
	pr_err("Trying UAF...\n");
	ptr = kmalloc(128, GFP_KERNEL);
	kfree(ptr);
	*(ptr + 126 - 64) = 'x';
}

void do_access_redzone(void)
{
	char *ptr;
	pr_err("Trying to access redzone...\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 18) = 'x';
	kfree(ptr);
}

void do_uaf_memset(void)
{
	char *ptr;
	pr_err("Trying UAF in memcpy...\n");
	ptr = kmalloc(33, GFP_KERNEL);
	kfree(ptr);
	memset(ptr, 0, 30);
}
