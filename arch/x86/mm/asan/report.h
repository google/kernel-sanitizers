#ifndef __X86_MM_ASAN_REPORT_H
#define __X86_MM_ASAN_REPORT_H

void asan_report_error(unsigned long poisoned_addr);

#endif
