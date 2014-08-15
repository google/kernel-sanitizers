#include "asan.h"

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

int asan_error_counter; /* = 0 */
DEFINE_SPINLOCK(asan_error_counter_lock);

/* The format for all stats is "some_stat: N". */
static int asan_stats_show(struct seq_file *m, void *v)
{
	unsigned long flags;

	spin_lock_irqsave(&asan_error_counter_lock, flags);
	seq_printf(m, "errors: %d\n", asan_error_counter);
	seq_printf(m, "quarantine size: %ld\n", asan_quarantine_size());
	spin_unlock_irqrestore(&asan_error_counter_lock, flags);
	return 0;
}

static int asan_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, asan_stats_show, NULL);
}

static const struct file_operations asan_stats_operations = {
	.open		= asan_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release
};

static int __init asan_stats_init(void)
{
	proc_create("kasan_stats", S_IRUSR, NULL, &asan_stats_operations);
	return 0;
}

device_initcall(asan_stats_init);
