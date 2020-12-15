// SPDX-License-Identifier: GPL-2.0

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <trace/events/printk.h>

#define ERRCAP_BUF_SIZE PAGE_SIZE

struct kobject *errcap_kobj;

DEFINE_SPINLOCK(errcap_lock);
DEFINE_SPINLOCK(errcap_report_lock);

static char errcap_wip_report[ERRCAP_BUF_SIZE], errcap_report[ERRCAP_BUF_SIZE];
static size_t errcap_wip_pos, errcap_report_size;
static pid_t errcap_pid;
static unsigned int errcap_cpu;
static bool errcap_enabled;

void errcap_start_report(void)
{
	unsigned long flags;

	spin_lock_irqsave(&errcap_lock, flags);
	if (current) {
		errcap_pid = current->pid;
	} else {
		errcap_pid = 0;
		errcap_cpu = smp_processor_id();
	}
	errcap_wip_pos = 0;
	WRITE_ONCE(errcap_enabled, true);
	spin_unlock_irqrestore(&errcap_lock, flags);
}

void errcap_stop_report(void)
{
	unsigned long flags;
	spin_lock_irqsave(&errcap_lock, flags);
	WARN_ON(!READ_ONCE(errcap_enabled));
	WRITE_ONCE(errcap_enabled, false);
	spin_lock(&errcap_report_lock);
	if (errcap_wip_pos)
		memcpy(errcap_report, errcap_wip_report, errcap_wip_pos);
	errcap_report_size = errcap_wip_pos;
	if (errcap_report_size == ERRCAP_BUF_SIZE)
		errcap_report[errcap_report_size - 1] = 0;
	else
		errcap_report[errcap_report_size] = 0;
	spin_unlock(&errcap_report_lock);
	spin_unlock_irqrestore(&errcap_lock, flags);
	///sysfs_notify(errcap_kobj, NULL, "errcap_report");
}

ssize_t errcap_report_read(struct file *file, char __user *buf, size_t len,
			   loff_t *offset)
{
	unsigned long flags;
	ssize_t res;

	spin_lock_irqsave(&errcap_report_lock, flags);
	if (errcap_report_size)
		res = simple_read_from_buffer(buf, len, offset, errcap_report,
					      errcap_report_size);
	else
		res = 0;
	spin_unlock_irqrestore(&errcap_report_lock, flags);
	if (res > 0)
		*offset += res;
	return res;
}

static void errcap_probe_console(void *ignore, const char *buf, size_t len)
{
	unsigned long flags;
	size_t to_copy;

	if (!READ_ONCE(errcap_enabled))
		return;
	if (current) {
		if (errcap_pid != current->pid)
			return;
	} else {
		if (errcap_cpu != smp_processor_id())
			return;
	}

	spin_lock_irqsave(&errcap_lock, flags);
	to_copy = min(len, ERRCAP_BUF_SIZE - errcap_wip_pos);
	memcpy(errcap_wip_report + errcap_wip_pos, buf, to_copy);
	errcap_wip_pos += to_copy;
	spin_unlock_irqrestore(&errcap_lock, flags);
}

static void register_tracepoints(struct tracepoint *tp, void *ignore)
{
	check_trace_callback_type_console(errcap_probe_console);
	if (!strcmp(tp->name, "console"))
		WARN_ON(tracepoint_probe_register(tp, errcap_probe_console,
						  NULL));
}

static ssize_t errcap_report_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, errcap_report);
}

static struct kobj_attribute errcap_report_attr = __ATTR_RO(errcap_report);
static struct attribute *errcap_sysfs_attrs[] = {
	&errcap_report_attr.attr,
	NULL,
};

static const struct attribute_group errcap_sysfs_attr_group = {
	.attrs = errcap_sysfs_attrs,
};

static int errcap_setup(void)
{
	int err;

	for_each_kernel_tracepoint(register_tracepoints, NULL);
	errcap_kobj = kobject_create_and_add("errcap", mm_kobj);
	if (!errcap_kobj)
		return -ENOMEM;
	err = sysfs_create_group(errcap_kobj, &errcap_sysfs_attr_group);
	if (err)
		return -ENOMEM;
	return 0;
}
late_initcall(errcap_setup);
