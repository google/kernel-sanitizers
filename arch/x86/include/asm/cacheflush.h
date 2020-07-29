/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CACHEFLUSH_H
#define _ASM_X86_CACHEFLUSH_H

#include <linux/mm.h>

/* Caches aren't brain-dead on the intel. */
#include <asm-generic/cacheflush.h>
#include <asm/special_insns.h>

void clflush_cache_range(void *addr, unsigned int size);

static inline int l1d_flush_hw(void)
{
	if (static_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		wrmsrl(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
		return 0;
	}
	return -EOPNOTSUPP;
}
#endif /* _ASM_X86_CACHEFLUSH_H */
