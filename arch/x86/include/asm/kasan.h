#ifndef _ASM_X86_KASAN_H
#define _ASM_X86_KASAN_H

#define KASAN_SHADOW_START	0xffffd90000000000UL
#define KASAN_SHADOW_END	0xffffe90000000000UL

#ifndef __ASSEMBLY__

extern pte_t zero_pte[];
extern pte_t zero_pmd[];
extern pte_t zero_pud[];

extern pte_t poisoned_pte[];
extern pte_t poisoned_pmd[];
extern pte_t poisoned_pud[];

#ifdef CONFIG_KASAN
void __init kasan_map_zero_shadow(pgd_t *pgd);
void __init kasan_map_shadow(void);
#else
static inline void kasan_map_zero_shadow(pgd_t *pgd) { }
static inline void kasan_map_shadow(void) { }
#endif

#endif

#endif
