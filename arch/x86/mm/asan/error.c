#include <linux/slab.h>

void do_use_after_free(void)
{
	char *ptr = (char *)kmalloc(10, GFP_KERNEL);
	printk(KERN_ERR "kmalloc: %lx", (unsigned long)ptr);
	kfree(ptr);
	*ptr = 'x';
}
