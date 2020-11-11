/* SPDX-License-Identifier: GPL-2.0.-or-later */
/*
 * Stack cache interface
 *
 * Copyright (C) 2020 Google, Inc.
 *
 */

#ifndef _LINUX_STACKCACHE_H
#define _LINUX_STACKCACHE_H

#include <linux/types.h>

#define STACK_CACHE_MAX_DEPTH 32

/**
 * stack_cache_insert - Add a new stack trace record to the cache.
 * @object: Pointer to the start of the object.
 * @size: Size of the object (in bytes).
 * @trace_type: Called-defined value that determines the type of the stack trace.
 * @n_entries: The number of stack trace entries.
 * @entries: Stack trace entries.
 *
 * This function runs in O(1).
 */
void stack_cache_insert(const volatile void *object, size_t size, unsigned trace_type,
						size_t n_entries, const unsigned long *entries);

/**
 * struct stack_cache_response - a stack trace cache response entry.
 * @object: Pointer to the start of the object.
 * @size: Size of the object (in bytes).
 * @trace_type: Type of the stack trace.
 * @n_entries: The number of stack trace entries.
 * @entries: Stack trace entries.
 *
 * The structure is intended to be used for querying stack cache entries.
 */
struct stack_cache_response {
	void *object;
	size_t size;
	unsigned trace_type;
	size_t n_entries;
	unsigned long entries[STACK_CACHE_MAX_DEPTH];
};

/**
 * stack_cache_lookup - Query possible stack cache entries for objects that were located as close
 * to [@ptr;@ptr+@size] as possible.
 * @ptr: Pointer to the target memory location.
 * @size: Size of the memory access.
 * @entries: A pointer to an array of struct stack_cache_response that will store the response.
 * @nentries: The number of elements in @entries
 *
 * The method generates a sorted sequence of distinct stack trace cache entries. The ordering is
 * as follows.
 * 1. Firstly, the method attempts to find traces for objects that contained @ptr. Latest records
 *    will appear first.
 * 2. Other elements come in order of increasing distance from @ptr.
 *
 * Return: the number of saved entries.
 */

size_t stack_cache_lookup(const volatile void *ptr, size_t size,
						  struct stack_cache_response *entries, unsigned int nentries);

#endif /* _LINUX_STACKCACHE_H */
