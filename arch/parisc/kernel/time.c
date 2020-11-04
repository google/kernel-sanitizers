// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/parisc/kernel/time.c
 *
 *  Copyright (C) 1991, 1992, 1995  Linus Torvalds
 *  Modifications for ARM (C) 1994, 1995, 1996,1997 Russell King
 *  Copyright (C) 1999 SuSE GmbH, (Philipp Rumpf, prumpf@tux.org)
 *
 * 1994-07-02  Alan Modra
 *             fixed set_rtc_mmss, fixed time.year for >= 2000, new mktime
 * 1998-12-20  Updated NTP code according to technical memorandum Jan '96
 *             "A Kernel Model for Precision Timekeeping" by Dave Mills
 */
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/rtc.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>
#include <linux/sched_clock.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/clockchips.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/clocksource.h>
#include <linux/platform_device.h>
#include <linux/ftrace.h>

#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/page.h>
#include <asm/param.h>
#include <asm/pdc.h>
#include <asm/led.h>

#include <linux/timex.h>

/*
 * The PA-RISC Interval Timer is a pair of registers; one is read-only and one
 * is write-only; both accessed through CR16.  The read-only register is 32 or
 * 64 bits wide, and increments by 1 every CPU clock tick.  The architecture
 * only guarantees us a rate between 0.5 and 2, but all implementations use a
 * rate of 1.  The write-only register is 32-bits wide.  When the lowest 32
 * bits of the read-only register compare equal to the write-only register, it
 * raises a maskable external interrupt.  Each processor has an Interval Timer
 * of its own and they are not synchronised.
 */

#define cr16_hz	(100 * PAGE0->mem_10msec)	/* Hz */
static unsigned long clocktick __ro_after_init;	/* timer cycles per tick */

static DEFINE_PER_CPU(struct clock_event_device, hppa_clk_events);

/*
 * Do not disable the timer irq. The clockevents get that frequently
 * programmed, that it's unlikely the timer will wrap and trigger again. So
 * it's not worth to disable and reenable the hardware irqs, instead store in a
 * static per-cpu variable if the irq is expected or not.
 */
static DEFINE_PER_CPU(bool, cr16_clockevent_enabled);

static void cr16_set_next(unsigned long delta, bool reenable_irq)
{
	mtctl(mfctl(16) + delta, 16);

	if (reenable_irq)
		per_cpu(cr16_clockevent_enabled, smp_processor_id()) = true;
}

static int cr16_clockevent_shutdown(struct clock_event_device *evt)
{
	per_cpu(cr16_clockevent_enabled, smp_processor_id()) = false;
	return 0;
}

static int cr16_clockevent_set_periodic(struct clock_event_device *evt)
{
	cr16_set_next(clocktick, true);
	return 0;
}

static int cr16_clockevent_set_next_event(unsigned long delta,
					struct clock_event_device *evt)
{
	cr16_set_next(delta, true);
	return 0;
}

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	unsigned int cpu = smp_processor_id();
	struct clock_event_device *evt;
	bool handle_irq;

	evt = &per_cpu(hppa_clk_events, cpu);
	handle_irq = per_cpu(cr16_clockevent_enabled, cpu);

	if (clockevent_state_oneshot(evt))
		per_cpu(cr16_clockevent_enabled, smp_processor_id()) = false;
	else {
		if (handle_irq)
			cr16_set_next(clocktick, false);
	}

	if (handle_irq)
		evt->event_handler(evt);

	return IRQ_HANDLED;
}


unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (regs->gr[0] & PSW_N)
		pc -= 4;

#ifdef CONFIG_SMP
	if (in_lock_functions(pc))
		pc = regs->gr[2];
#endif

	return pc;
}
EXPORT_SYMBOL(profile_pc);


/* clock source code */

static u64 notrace read_cr16(struct clocksource *cs)
{
	return get_cycles();
}

static struct clocksource clocksource_cr16 = {
	.name			= "cr16",
	.rating			= 300,
	.read			= read_cr16,
	.mask			= CLOCKSOURCE_MASK(BITS_PER_LONG),
	.flags			= CLOCK_SOURCE_IS_CONTINUOUS,
};

void __init start_cpu_itimer(void)
{
	unsigned int cpu = smp_processor_id();

	struct clock_event_device *clk = this_cpu_ptr(&hppa_clk_events);

	clk->name = "cr16";
	clk->features = CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT |
			CLOCK_EVT_FEAT_PERCPU;
	clk->set_state_shutdown = cr16_clockevent_shutdown;
	clk->set_state_periodic = cr16_clockevent_set_periodic;
	clk->set_state_oneshot = cr16_clockevent_shutdown;
	clk->set_state_oneshot_stopped = cr16_clockevent_shutdown;
	clk->set_next_event = cr16_clockevent_set_next_event;
	clk->cpumask = cpumask_of(cpu);
	clk->rating = 300;
	clk->irq = TIMER_IRQ;
	clockevents_config_and_register(clk, cr16_hz, 4000, 0xffffffff);

	if (cpu == 0) {
		int err = request_percpu_irq(TIMER_IRQ, timer_interrupt,
					 "timer", clk);
		BUG_ON(err);
	}

	enable_percpu_irq(clk->irq, IRQ_TYPE_NONE);
}

#if IS_ENABLED(CONFIG_RTC_DRV_GENERIC)
static int rtc_generic_get_time(struct device *dev, struct rtc_time *tm)
{
	struct pdc_tod tod_data;

	memset(tm, 0, sizeof(*tm));
	if (pdc_tod_read(&tod_data) < 0)
		return -EOPNOTSUPP;

	/* we treat tod_sec as unsigned, so this can work until year 2106 */
	rtc_time64_to_tm(tod_data.tod_sec, tm);
	return 0;
}

static int rtc_generic_set_time(struct device *dev, struct rtc_time *tm)
{
	time64_t secs = rtc_tm_to_time64(tm);
	int ret;

	/* hppa has Y2K38 problem: pdc_tod_set() takes an u32 value! */
	ret = pdc_tod_set(secs, 0);
	if (ret != 0) {
		pr_warn("pdc_tod_set(%lld) returned error %d\n", secs, ret);
		if (ret == PDC_INVALID_ARG)
			return -EINVAL;
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct rtc_class_ops rtc_generic_ops = {
	.read_time = rtc_generic_get_time,
	.set_time = rtc_generic_set_time,
};

static int __init rtc_init(void)
{
	struct platform_device *pdev;

	pdev = platform_device_register_data(NULL, "rtc-generic", -1,
					     &rtc_generic_ops,
					     sizeof(rtc_generic_ops));

	return PTR_ERR_OR_ZERO(pdev);
}
device_initcall(rtc_init);
#endif

void read_persistent_clock64(struct timespec64 *ts)
{
	static struct pdc_tod tod_data;
	if (pdc_tod_read(&tod_data) == 0) {
		ts->tv_sec = tod_data.tod_sec;
		ts->tv_nsec = tod_data.tod_usec * 1000;
	} else {
		printk(KERN_ERR "Error reading tod clock\n");
	        ts->tv_sec = 0;
		ts->tv_nsec = 0;
	}
}


static u64 notrace read_cr16_sched_clock(void)
{
	return get_cycles();
}


/*
 * timer interrupt and sched_clock() initialization
 */

void __init time_init(void)
{
	clocktick = DIV_ROUND_CLOSEST(cr16_hz, HZ);
	start_cpu_itimer();	/* get CPU 0 started */

	/* register as sched_clock source */
	sched_clock_register(read_cr16_sched_clock, BITS_PER_LONG, cr16_hz);
}

static int __init init_cr16_clocksource(void)
{
	/*
	 * The cr16 interval timers are not syncronized across CPUs on
	 * different sockets, so mark them unstable and lower rating on
	 * multi-socket SMP systems.
	 */
	if (num_online_cpus() > 1 && !running_on_qemu) {
		int cpu;
		unsigned long cpu0_loc;
		cpu0_loc = per_cpu(cpu_data, 0).cpu_loc;

		for_each_online_cpu(cpu) {
			if (cpu == 0)
				continue;
			if ((cpu0_loc != 0) &&
			    (cpu0_loc == per_cpu(cpu_data, cpu).cpu_loc))
				continue;

			clocksource_cr16.name = "cr16_unstable";
			clocksource_cr16.flags = CLOCK_SOURCE_UNSTABLE;
			clocksource_cr16.rating = 0;
			break;
		}
	}

	/* XXX: We may want to mark sched_clock stable here if cr16 clocks are
	 *	in sync:
	 *	(clocksource_cr16.flags == CLOCK_SOURCE_IS_CONTINUOUS) */

	/* register at clocksource framework */
	clocksource_register_hz(&clocksource_cr16,
		100 * PAGE0->mem_10msec);

	return 0;
}

device_initcall(init_cr16_clocksource);
