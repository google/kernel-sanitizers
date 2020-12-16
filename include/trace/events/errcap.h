#undef TRACE_SYSTEM
#define TRACE_SYSTEM errcap

#if !defined(_TRACE_ERRCAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ERRCAP_H

#include <linux/tracepoint.h>

TRACE_EVENT(error_report_start,
	TP_PROTO(unsigned long opaque_id),
	TP_ARGS(opaque_id),
	TP_STRUCT__entry(
		__field(unsigned long, opaque_id)
	),
	TP_fast_assign(
		__entry->opaque_id = opaque_id;
	),
	TP_printk("error_report_start: %lx", __entry->opaque_id)
);

TRACE_EVENT(error_report_end,
	TP_PROTO(unsigned long opaque_id),
	TP_ARGS(opaque_id),
	TP_STRUCT__entry(
		__field(unsigned long, opaque_id)
	),
	TP_fast_assign(
		__entry->opaque_id = opaque_id;
	),
	TP_printk("error_report_end: %lx", __entry->opaque_id)
);

#endif /* _TRACE_ERRCAP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
