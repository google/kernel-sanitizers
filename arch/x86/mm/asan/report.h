#ifndef __X86_MM_ASAN_REPORT_H
#define __X86_MM_ASAN_REPORT_H

#include <linux/types.h>

void asan_report_error(unsigned long poisoned_addr,
		       unsigned long access_size, bool is_write);

#endif
