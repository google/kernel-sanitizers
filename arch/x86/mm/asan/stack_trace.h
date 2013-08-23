#ifndef ASAN_STACK_TRACE_H_
#define ASAN_STACK_TRACE_H_

unsigned int asan_save_stack_trace(unsigned long *stack,
				   unsigned int max_entries);
void asan_print_stack_trace(unsigned long *stack, unsigned int max_entries);
void asan_print_current_stack_trace(void);

#endif
