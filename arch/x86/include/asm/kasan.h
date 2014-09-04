#ifndef _ASM_X86_KASAN_H
#define _ASM_X86_KASAN_H

#define KASAN_SHADOW_START	0xffff800000000000UL
#define KASAN_SHADOW_END	0xffff900000000000UL

#ifndef __ASSEMBLY__
extern pte_t zero_pte[];
extern pte_t zero_pmd[];
extern pte_t zero_pud[];

#ifdef CONFIG_KASAN
void __init kasan_map_zero_shadow(pgd_t *pgd);
#else
static inline void kasan_map_zero_shadow(pgd_t *pgd) { }
#endif

#endif

#endif
