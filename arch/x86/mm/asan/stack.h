#ifndef ASAN_STACK_H_
#define ASAN_STACK_H_

void asan_save_stack(unsigned long *stack, unsigned long max_entries);
void asan_print_stack(unsigned long *stack, unsigned long entries);
void asan_print_current_stack(void);

#endif
