/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM error_report

#if !defined(_TRACE_ERROR_REPORT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ERROR_REPORT_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(error_report_template,
		    TP_PROTO(const char *tool_name, unsigned long id),
		    TP_ARGS(tool_name, id),
		    TP_STRUCT__entry(__field(const char *, tool_name)
					     __field(unsigned long, id)),
		    TP_fast_assign(__entry->tool_name = tool_name;
				   __entry->id = id;),
		    TP_printk("[%s] %lx", __entry->tool_name, __entry->id));

DEFINE_EVENT(error_report_template, error_report_start,
	     TP_PROTO(const char *tool_name, unsigned long id),
	     TP_ARGS(tool_name, id));

DEFINE_EVENT(error_report_template, error_report_end,
	     TP_PROTO(const char *tool_name, unsigned long id),
	     TP_ARGS(tool_name, id));

#endif /* _TRACE_ERROR_REPORT_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
