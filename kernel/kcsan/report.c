/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>

#include "kcsan.h"
#include "encoding.h"

/*
 * Max. number of stack entries to show in the report.
 */
#define NUM_STACK_ENTRIES 16

/*
 * Other thread info: communicated from other racing thread to thread that set
 * up the watchpoint, which then prints the complete report atomically. Only
 * need one struct, as all threads should to be serialized regardless to print
 * the reports, with reporting being in the slow-path.
 */
static struct {
	const volatile void *ptr;
	size_t size;
	bool is_write;
	int task_pid;
	int cpu_id;
	unsigned long stack_entries[NUM_STACK_ENTRIES];
	int num_stack_entries;
} other_info = { .ptr = NULL };

static DEFINE_SPINLOCK(other_info_lock);
static DEFINE_SPINLOCK(report_lock);

static bool set_or_lock_other_info(unsigned long *flags,
				   const volatile void *ptr, size_t size,
				   bool is_write, int cpu_id,
				   enum kcsan_report_type type)
{
	if (type != kcsan_report_race_check && type != kcsan_report_race_setup)
		return true;

	for (;;) {
		spin_lock_irqsave(&other_info_lock, *flags);

		switch (type) {
		case kcsan_report_race_check:
			if (other_info.ptr != NULL) {
				/* still in use, retry */
				break;
			}
			other_info.ptr = ptr;
			other_info.size = size;
			other_info.is_write = is_write;
			other_info.task_pid =
				in_task() ? task_pid_nr(current) : -1;
			other_info.cpu_id = cpu_id;
			other_info.num_stack_entries = stack_trace_save(
				other_info.stack_entries, NUM_STACK_ENTRIES, 1);
			/* other_info may now be consumed by thread we raced with */
			spin_unlock_irqrestore(&other_info_lock, *flags);
			return false;

		case kcsan_report_race_setup:
			if (other_info.ptr == NULL)
				break; /* no data available yet, retry */

			/*
			 * First check if matching based on how watchpoint was
			 * encoded.
			 */
			if (!matching_access((unsigned long)other_info.ptr &
						     WATCHPOINT_ADDR_MASK,
					     other_info.size,
					     (unsigned long)ptr &
						     WATCHPOINT_ADDR_MASK,
					     size))
				break; /* mismatching access, retry */

			if (!matching_access((unsigned long)other_info.ptr,
					     other_info.size,
					     (unsigned long)ptr, size)) {
				/*
				 * If the actual accesses to not match, this was
				 * a false positive due to watchpoint encoding.
				 */
				other_info.ptr = NULL; /* mark for reuse */
				kcsan_counter_inc(
					kcsan_counter_encoding_false_positive);
				spin_unlock_irqrestore(&other_info_lock,
						       *flags);
				return false;
			}

			/*
			 * Matching access: keep other_info locked, as this
			 * thread uses it to print the full report; unlocked in
			 * end_report.
			 */
			return true;

		default:
			BUG();
		}

		spin_unlock_irqrestore(&other_info_lock, *flags);
	}
}

static void start_report(unsigned long *flags, enum kcsan_report_type type)
{
	switch (type) {
	case kcsan_report_race_setup:
		/* irqsaved already via other_info_lock */
		spin_lock(&report_lock);
		break;

	case kcsan_report_race_diff:
		spin_lock_irqsave(&report_lock, *flags);
		break;

	default:
		BUG();
	}

	pr_err("==================================================================\n");
}

static void end_report(unsigned long *flags, enum kcsan_report_type type)
{
	pr_err("==================================================================\n");
	if (panic_on_warn)
		panic("panic_on_warn set ...\n");

	switch (type) {
	case kcsan_report_race_setup:
		other_info.ptr = NULL; /* mark for reuse */
		spin_unlock(&report_lock);
		spin_unlock_irqrestore(&other_info_lock, *flags);
		break;

	case kcsan_report_race_diff:
		spin_unlock_irqrestore(&report_lock, *flags);
		break;

	default:
		BUG();
	}
}

static const char *get_access_type(bool is_write)
{
	return is_write ? "write" : "read";
}

/* Return thread description: in task or interrupt. */
static const char *get_thread_desc(int task_id)
{
	if (task_id != -1) {
		static char buf[32]; /* safe: reporting protected by lock */
		snprintf(buf, sizeof(buf), "task %i", task_id);
		return buf;
	}
	return in_nmi() ? "NMI" : "interrupt";
}

/* Helper to skip KCSAN-related functions in stack-trace. */
static int get_stack_skipnr(unsigned long stack_entries[], int num_entries)
{
	char buf[64];
	int skip = 0;
	for (; skip < num_entries; ++skip) {
		snprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
		if (!strnstr(buf, "csan_", sizeof(buf)) &&
		    !strnstr(buf, "tsan_", sizeof(buf)) &&
		    !strnstr(buf, "_once_size", sizeof(buf))) {
			break;
		}
	}
	return skip;
}

/* Compares symbolized strings of addr1 and addr2. */
static int sym_strcmp(void *addr1, void *addr2)
{
	char buf1[32];
	char buf2[32];
	snprintf(buf1, sizeof(buf1), "%pS", addr1);
	snprintf(buf2, sizeof(buf2), "%pS", addr2);
	return strncmp(buf1, buf2, sizeof(buf1));
}

static void print_summary(const volatile void *ptr, size_t size, bool is_write,
			  int cpu_id, enum kcsan_report_type type)
{
	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
	const int num_stack_entries =
		stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
	const int stack_skipnr =
		get_stack_skipnr(stack_entries, num_stack_entries);
	const int other_stack_skipnr =
		type == kcsan_report_race_setup ?
			get_stack_skipnr(other_info.stack_entries,
					 other_info.num_stack_entries) :
			0;

	switch (type) {
	case kcsan_report_race_setup: {
		void *other_fn =
			(void *)other_info.stack_entries[other_stack_skipnr];
		void *this_fn = (void *)stack_entries[stack_skipnr];
		/*
		 * Order functions lexographically for consistent bug titles.
		 * Do not print offset of functions to keep title short.
		 */
		int c = sym_strcmp(other_fn, this_fn);
		pr_err("BUG: KCSAN: data-race in %ps / %ps\n",
		       c < 0 ? other_fn : this_fn, c < 0 ? this_fn : other_fn);
	} break;

	case kcsan_report_race_diff:
		pr_err("BUG: KCSAN: racing %s in %pS\n",
		       get_access_type(is_write),
		       (void *)stack_entries[stack_skipnr]);
		break;

	default:
		BUG();
	}

	pr_err("\n");

	switch (type) {
	case kcsan_report_race_setup:
		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
		       get_access_type(other_info.is_write), other_info.ptr,
		       other_info.size, get_thread_desc(other_info.task_pid),
		       other_info.cpu_id);
		stack_trace_print(
			other_info.stack_entries + other_stack_skipnr,
			other_info.num_stack_entries - other_stack_skipnr, 0);

		pr_err("\n");
		pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
		       get_access_type(is_write), ptr, size,
		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
		       cpu_id);
		break;

	case kcsan_report_race_diff:
		pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
		       get_access_type(is_write), ptr, size,
		       get_thread_desc(in_task() ? task_pid_nr(current) : -1),
		       cpu_id);
		break;

	default:
		BUG();
	}

	stack_trace_print(stack_entries + stack_skipnr,
			  num_stack_entries - stack_skipnr, 0);
	pr_err("\n");

	pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
	dump_stack_print_info(KERN_DEFAULT);
}

void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
		  int cpu_id, enum kcsan_report_type type)
{
	unsigned long flags = 0;

	if (type == kcsan_report_race_check_race)
		return;

	kcsan_disable_current();
	if (set_or_lock_other_info(&flags, ptr, size, is_write, cpu_id, type)) {
		start_report(&flags, type);
		print_summary(ptr, size, is_write, cpu_id, type);
		end_report(&flags, type);
	}
	kcsan_enable_current();
}
