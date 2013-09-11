#ifndef ASAN_THREAD_H_
#define ASAN_THREAD_H_

#include <linux/types.h>

pid_t asan_get_current_thread_id(void);

#endif
