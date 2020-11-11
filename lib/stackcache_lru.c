// SPDX-License-Identifier: GPL-2.0
/*
 * LRU-cache based implementation for stackcache.
 *
 * Copyright (C) 2020, Google Inc.
 */

#include <linux/stackcache.h>

void stack_cache_insert(const volatile void *object, size_t size, unsigned trace_type,
						size_t n_entries, const unsigned long *entries)
{
}


size_t stack_cache_lookup(const volatile void *ptr, size_t size,
						  struct stack_cache_response *entries, unsigned int nentries)
{
	return 0;
}
