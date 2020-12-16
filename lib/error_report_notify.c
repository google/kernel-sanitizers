// SPDX-License-Identifier: GPL-2.0

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/workqueue.h>
#include <trace/events/error_report.h>
#include <trace/events/printk.h>

static struct kobject *error_report_kobj;
static atomic_t num_error_reports;

static DEFINE_SPINLOCK(current_lock);
static DEFINE_SPINLOCK(report_lock);

static char current_report[PAGE_SIZE], last_report[PAGE_SIZE];
static size_t current_report_pos, last_report_size;
static pid_t current_pid;
static unsigned int current_cpu;
static bool capturing_enabled;
static struct delayed_work reporting_done;

static void error_report_notify(struct work_struct *work)
{
	sysfs_notify(error_report_kobj, NULL, "last_report");
	sysfs_notify(error_report_kobj, NULL, "report_count");
}
static DECLARE_DELAYED_WORK(reporting_done, error_report_notify);

/*
 * Trace hook for the error_report_start event. If two reports overlap (the
 * second one report is started before the first one is finished, the first
 * report is discarded.
 */
static void probe_report_start(void *ignore, const char *tool_name,
			       unsigned long id)
{
	unsigned long flags;

	spin_lock_irqsave(&current_lock, flags);
	if (current) {
		current_pid = current->pid;
	} else {
		current_pid = 0;
		current_cpu = smp_processor_id();
	}
	current_report_pos = 0;
	WRITE_ONCE(capturing_enabled, true);
	spin_unlock_irqrestore(&current_lock, flags);
}

bool is_same_context(void)
{
	if (current) {
		if (current_pid != current->pid)
			return false;
	} else {
		if (current_cpu != smp_processor_id())
			return false;
	}
	return true;
}

/*
 * Trace hook for the error_report_end event. If a stale event from the
 * mismatching error_report_start is received, it is ignored.
 */
static void probe_report_end(void *ignore, const char *tool_name,
			     unsigned long id)
{
	unsigned long flags;
	spin_lock_irqsave(&current_lock, flags);
	WARN_ON(!READ_ONCE(capturing_enabled));
	WRITE_ONCE(capturing_enabled, false);
	spin_lock(&report_lock);
	if (!is_same_context()) {
		spin_unlock(&report_lock);
		spin_unlock_irqrestore(&current_lock, flags);
		return;
	}
	if (current_report_pos)
		memcpy(last_report, current_report, current_report_pos);
	last_report_size = current_report_pos;
	if (last_report_size == sizeof(last_report))
		last_report[last_report_size - 1] = 0;
	else
		last_report[last_report_size] = 0;
	spin_unlock(&report_lock);
	spin_unlock_irqrestore(&current_lock, flags);
	atomic_inc(&num_error_reports);
	schedule_delayed_work(&reporting_done, 0);
}

ssize_t last_report_read(struct file *file, char __user *buf, size_t len,
			 loff_t *offset)
{
	unsigned long flags;
	ssize_t res;

	spin_lock_irqsave(&report_lock, flags);
	if (last_report_size)
		res = simple_read_from_buffer(buf, len, offset, last_report,
					      last_report_size);
	else
		res = 0;
	spin_unlock_irqrestore(&report_lock, flags);
	if (res > 0)
		*offset += res;
	return res;
}

/*
 * Trace hook for the console event. If a line comes from a task/CPU that did
 * not send the error_report_start event, that line is ignored.
 */
static void probe_console(void *ignore, const char *buf, size_t len)
{
	unsigned long flags;
	size_t to_copy;

	if (!READ_ONCE(capturing_enabled))
		return;
	if (!is_same_context())
		return;

	spin_lock_irqsave(&current_lock, flags);
	to_copy = min(len, sizeof(current_report) - current_report_pos);
	memcpy(current_report + current_report_pos, buf, to_copy);
	current_report_pos += to_copy;
	spin_unlock_irqrestore(&current_lock, flags);
}

static void register_tracepoints(void)
{
	register_trace_console(probe_console, NULL);
	register_trace_error_report_start(probe_report_start, NULL);
	register_trace_error_report_end(probe_report_end, NULL);
}

static ssize_t last_report_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, last_report);
}

static ssize_t report_count_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&num_error_reports));
}

static struct kobj_attribute last_report_attr = __ATTR_RO(last_report);
static struct kobj_attribute report_count_attr = __ATTR_RO(report_count);
static struct attribute *error_report_sysfs_attrs[] = {
	&last_report_attr.attr,
	&report_count_attr.attr,
	NULL,
};

static const struct attribute_group error_report_sysfs_attr_group = {
	.attrs = error_report_sysfs_attrs,
};

static void error_report_notify_setup(void)
{
	int err;

	register_tracepoints();
	error_report_kobj = kobject_create_and_add("error_report", kernel_kobj);
	if (!error_report_kobj)
		goto error;
	err = sysfs_create_group(error_report_kobj,
				 &error_report_sysfs_attr_group);
	if (err)
		goto error;
	return;

error:
	if (error_report_kobj)
		kobject_del(error_report_kobj);
}
late_initcall(error_report_notify_setup);
