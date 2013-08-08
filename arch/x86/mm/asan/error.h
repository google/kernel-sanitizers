#ifndef ASAN_ERROR_H_
#define ASAN_ERROR_H_

void do_use_after_free(void);
void do_access_redzone(void);
void do_uaf_memcpy(void);

#endif /* ASAN_ERROR_H_ */
