/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_UM_CACHEFLUSH_H
#define _ASM_UM_CACHEFLUSH_H

#undef ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE
#include <asm-generic/cacheflush.h>

static inline int l1d_flush_hw(void) { return -EOPNOTSUPP; }
#endif /* _ASM_UM_CACHEFLUSH_H */
