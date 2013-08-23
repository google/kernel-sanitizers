#include "thread.h"

#include <linux/sched.h>
#include <linux/types.h>

#include <asm/thread_info.h>

pid_t get_current_thread_id(void)
{
	return current_thread_info()->task->pid;
}

