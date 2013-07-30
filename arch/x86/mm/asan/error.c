#include <linux/printk.h>
#include <linux/slab.h>

void do_use_after_free(void)
{
	pr_err("Trying 'use after free'...\n");
	char *ptr = kmalloc(128, GFP_KERNEL);
	kfree(ptr);
	*(ptr + 126 - 64) = 'x';
}

void do_access_redzone(void)
{
	pr_err("Trying to access redzone...\n");
	char *ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 18) = 'x';
	kfree(ptr);
}
