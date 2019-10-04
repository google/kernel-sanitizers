/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "kcsan.h"

static atomic_long_t counters[kcsan_counter_count];

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

/*
 * Shows if KCSAN is enabled, as well as all current counter values.
 */
static int show_info(struct seq_file *file, void *v)
{
	int i;

	seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
	for (i = 0; i < kcsan_counter_count; ++i) {
		seq_printf(file, "%s: %ld\n", counter_to_name(i),
			   atomic_long_read(&counters[i]));
	}

	return 0;
}

static int info_open(struct inode *inode, struct file *file)
{
	return single_open(file, show_info, NULL);
}

static ssize_t info_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *off)
{
	char kbuf[4]; /* "on", "off" + '\0' */
	int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, read_len))
		return -EINVAL;
	kbuf[read_len] = '\0';

	if (!strncmp(kbuf, "on", sizeof("on") - 1)) {
		WRITE_ONCE(kcsan_enabled, true);
	} else if (!strncmp(kbuf, "off", sizeof("off") - 1)) {
		WRITE_ONCE(kcsan_enabled, false);
	} else
		return -EINVAL;

	return count;
}

static const struct file_operations info_ops = { .read = seq_read,
						 .open = info_open,
						 .write = info_write,
						 .release = single_release };

void __init kcsan_info_init(void)
{
	memset(&counters, 0, sizeof(counters));
	proc_create("kcsaninfo", 0644, NULL, &info_ops);
}
