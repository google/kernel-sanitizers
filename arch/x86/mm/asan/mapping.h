#ifndef ASAN_MAPPING_H_
#define ASAN_MAPPING_H_

#include <linux/types.h>

extern unsigned long max_pfn;

bool addr_is_in_mem(unsigned long addr);

unsigned long mem_to_shadow(unsigned long addr);
unsigned long shadow_to_mem(unsigned long shadow_addr);

#endif
