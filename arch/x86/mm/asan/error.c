#include <linux/slab.h>

void do_use_after_free(void)
{
	char *ptr = kmalloc(128, GFP_KERNEL);
	kfree(ptr);
	*(ptr + 126 - 64) = 'x';
}

void do_access_redzone(void)
{
	/* XXX: kmalloc puts the object in the 32B cache */
	char *ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 33) = 'x';
}
