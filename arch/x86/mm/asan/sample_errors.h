#ifndef ASAN_ERROR_H_
#define ASAN_ERROR_H_

void do_bo(void);
void do_bo_left(void);
void do_bo_kmalloc(void);
void do_bo_krealloc(void);
void do_bo_krealloc_less(void);
void do_krealloc_more(void);
void do_uaf(void);
void do_uaf_memset(void);
void do_uaf_quarantine(void);

#endif /* ASAN_ERROR_H_ */
