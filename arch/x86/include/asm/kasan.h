#ifndef _ASM_X86_KASAN_H
#define _ASM_X86_KASAN_H

#define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + (1ULL << 61) \
                                        - (16ULL<<40))
#define KASAN_SHADOW_END        (KASAN_SHADOW_START + (16ULL << 40))

#ifndef __ASSEMBLY__

extern pte_t zero_pte[];
extern pte_t zero_pmd[];
extern pte_t zero_pud[];

extern pte_t poisoned_pte[];
extern pte_t poisoned_pmd[];
extern pte_t poisoned_pud[];

#ifdef CONFIG_KASAN
void __init kasan_map_zero_shadow(pgd_t *pgd);
void __init kasan_init(void);
#else
static inline void kasan_map_zero_shadow(pgd_t *pgd) { }
static inline void kasan_init(void) { }
#endif

#endif

#endif
