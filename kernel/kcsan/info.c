// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/bsearch.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kcsan.h"

/*
 * Statistics counters.
 */
static atomic_long_t counters[kcsan_counter_count];

/*
 * Addresses for functions blacklisted from reporting.
 */
static struct {
	unsigned long *addrs; /* array of addresses */
	size_t size; /* current size */
	int used; /* number of elements used */
	bool sorted; /* if elements are sorted */
} report_blacklist = {
	.addrs = NULL,
	.size = 8, /* small initial size */
	.used = 0,
	.sorted = false,
};
static DEFINE_SPINLOCK(report_blacklist_lock);

static const char *counter_to_name(enum kcsan_counter_id id)
{
	switch (id) {
	case kcsan_counter_used_watchpoints:
		return "used_watchpoints";
	case kcsan_counter_setup_watchpoints:
		return "setup_watchpoints";
	case kcsan_counter_race:
		return "race";
	case kcsan_counter_no_capacity:
		return "no_capacity";
	case kcsan_counter_race_report_race:
		return "race_report_race";
	case kcsan_counter_race_diff:
		return "race_diff";
	case kcsan_counter_unencodable_access:
		return "unencodable_access";
	case kcsan_counter_encoding_false_positive:
		return "encoding_false_positive";
	case kcsan_counter_count:
		BUG();
	}
	return NULL;
}

void kcsan_counter_inc(enum kcsan_counter_id id)
{
	atomic_long_inc(&counters[id]);
}

void kcsan_counter_dec(enum kcsan_counter_id id)
{
	atomic_long_dec(&counters[id]);
}

static int cmp_blacklist_addrs(const void *rhs, const void *lhs)
{
	const unsigned long a = *(const unsigned long *)rhs;
	const unsigned long b = *(const unsigned long *)lhs;

	return a < b ? -1 : a == b ? 0 : 1;
}

bool kcsan_skip_report(unsigned long func_addr)
{
	unsigned long symbolsize, offset;
	unsigned long flags;
	bool ret = false;

	if (!kallsyms_lookup_size_offset(func_addr, &symbolsize, &offset))
		return false;
	func_addr -= offset; /* get function start */

	spin_lock_irqsave(&report_blacklist_lock, flags);
	if (report_blacklist.used == 0)
		goto out;

	/* Sort array if it is unsorted, and then do a binary search. */
	if (!report_blacklist.sorted) {
		sort(report_blacklist.addrs, report_blacklist.used,
		     sizeof(unsigned long), cmp_blacklist_addrs, NULL);
		report_blacklist.sorted = true;
	}
	ret = !!bsearch(&func_addr, report_blacklist.addrs,
			report_blacklist.used, sizeof(unsigned long),
			cmp_blacklist_addrs);

out:
	spin_unlock_irqrestore(&report_blacklist_lock, flags);
	return ret;
}

static void insert_report_blacklist(const char *func)
{
	unsigned long flags;
	unsigned long addr = kallsyms_lookup_name(func);

	if (!addr) {
		pr_err("KCSAN: could not find function: '%s'\n", func);
		return;
	}

	spin_lock_irqsave(&report_blacklist_lock, flags);

	if (report_blacklist.addrs == NULL)
		report_blacklist.addrs = /* initial allocation */
			kvmalloc_array(report_blacklist.size,
				       sizeof(unsigned long), GFP_KERNEL);
	else if (report_blacklist.used == report_blacklist.size) {
		/* resize blacklist */
		unsigned long *new_addrs;

		report_blacklist.size *= 2;
		new_addrs = kvmalloc_array(report_blacklist.size,
					   sizeof(unsigned long), GFP_KERNEL);
		memcpy(new_addrs, report_blacklist.addrs,
		       report_blacklist.used * sizeof(unsigned long));
		kvfree(report_blacklist.addrs);
		report_blacklist.addrs = new_addrs;
	}

	/* Note: deduplicating should be done in userspace. */
	report_blacklist.addrs[report_blacklist.used++] =
		kallsyms_lookup_name(func);
	report_blacklist.sorted = false;

	spin_unlock_irqrestore(&report_blacklist_lock, flags);
}

static int show_info(struct seq_file *file, void *v)
{
	int i;
	unsigned long flags;

	/* show stats */
	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
	for (i = 0; i < kcsan_counter_count; ++i)
		seq_printf(file, "%s: %ld\n", counter_to_name(i),
			   atomic_long_read(&counters[i]));

	/* show blacklisted functions */
	spin_lock_irqsave(&report_blacklist_lock, flags);
	seq_printf(file, "\nblacklisted functions: %s\n",
		   report_blacklist.used == 0 ? "none" : "");
	for (i = 0; i < report_blacklist.used; ++i)
		seq_printf(file, " %ps\n", (void *)report_blacklist.addrs[i]);
	spin_unlock_irqrestore(&report_blacklist_lock, flags);

	return 0;
}

static int info_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_info, NULL);
}

static ssize_t info_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *off)
{
	char kbuf[KSYM_NAME_LEN];
	char *arg;
	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, buf, read_len))
		return -EINVAL;
	kbuf[read_len] = '\0';
	arg = strstrip(kbuf);

	if (!strncmp(arg, "on", sizeof("on") - 1))
		WRITE_ONCE(kcsan_enabled, true);
	else if (!strncmp(arg, "off", sizeof("off") - 1))
		WRITE_ONCE(kcsan_enabled, false);
	else if (arg[0] == '!')
		insert_report_blacklist(&arg[1]);
	else
		return -EINVAL;

	return count;
}

static const struct file_operations info_ops = { .read = seq_read,
						 .open = info_open,
						 .write = info_write,
						 .release = single_release };

void __init kcsan_info_init(void)
{
	debugfs_create_file("kcsan", 0644, NULL, NULL, &info_ops);
}
