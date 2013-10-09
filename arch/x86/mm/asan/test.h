#ifndef ASAN_ERROR_H_
#define ASAN_ERROR_H_

void asan_do_bo(void);
void asan_do_bo_left(void);
void asan_do_bo_kmalloc(void);
void asan_do_bo_kmalloc_node(void);
void asan_do_bo_krealloc(void);
void asan_do_bo_krealloc_less(void);
void asan_do_krealloc_more(void);
void asan_do_bo_16(void);
void asan_do_bo_4mb(void);
void asan_do_uaf(void);
void asan_do_uaf_memset(void);
void asan_do_uaf_quarantine(void);

#endif /* ASAN_ERROR_H_ */
