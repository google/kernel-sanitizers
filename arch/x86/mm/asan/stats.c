#include "asan.h"

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

static int asan_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "Reports: %d\n", asan_error_counter);
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

__initcall(asan_stats_init);
