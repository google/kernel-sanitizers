#ifndef ASAN_MAPPING_H_
#define ASAN_MAPPING_H_

extern unsigned long max_pfn;

inline int addr_is_in_mem(unsigned long addr);

unsigned long mem_to_shadow(unsigned long addr);

#endif
