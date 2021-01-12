/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM error_report

#if !defined(_TRACE_ERROR_REPORT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ERROR_REPORT_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(error_report_template,
		    TP_PROTO(const char *error_detector, unsigned long id),
		    TP_ARGS(error_detector, id),
		    TP_STRUCT__entry(__field(const char *, error_detector)
					     __field(unsigned long, id)),
		    TP_fast_assign(__entry->error_detector = error_detector;
				   __entry->id = id;),
		    TP_printk("[%s] %lx", __entry->error_detector,
			      __entry->id));

/**
 * error_report_start - called before printing the error report
 * @error_detector:	short string describing the error detection tool
 * @id:			pseudo-unique descriptor that can help distinguish reports
 * 			from one another. Depending on the tool, good examples
 * 			could be: memory access address, call site, allocation
 * 			site, etc.
 *
 * This event occurs right before a debugging tool starts printing the error
 * report.
 */
DEFINE_EVENT(error_report_template, error_report_start,
	     TP_PROTO(const char *error_detector, unsigned long id),
	     TP_ARGS(error_detector, id));

/**
 * error_report_end - called after printing the error report
 * @error_detector:	short string describing the error detection tool
 * @id:			pseudo-unique descriptor, matches that passed to
 * 			error_report_start
 *
 * This event occurs right after a debugging tool finishes printing the error
 * report.
 */
DEFINE_EVENT(error_report_template, error_report_end,
	     TP_PROTO(const char *error_detector, unsigned long id),
	     TP_ARGS(error_detector, id));

#endif /* _TRACE_ERROR_REPORT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
