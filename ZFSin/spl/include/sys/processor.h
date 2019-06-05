
#ifndef	_SPL_PROCESSOR_H
#define	_SPL_PROCESSOR_H

#include <sys/types.h>

#define _Bit(n)                 (1ULL << n)
#define _HBit(n)                (1ULL << ((n)+32))
#define CPUID_FEATURE_MMX       _Bit(23)  /* MMX supported */
#define CPUID_FEATURE_SSE       _Bit(25)  /* Streaming SIMD extensions */
#define CPUID_FEATURE_SSE2      _Bit(26)  /* Streaming SIMD extensions 2 */
#define CPUID_FEATURE_SSE3      _HBit(0)  /* Streaming SIMD extensions 3 */
#define CPUID_FEATURE_PCLMULQDQ _HBit(1)  /* PCLMULQDQ instruction */
#define CPUID_FEATURE_SSSE3     _HBit(9)  /* Supplemental SSE3 instructions */
#define CPUID_FEATURE_SSE4_1    _HBit(19) /* Streaming SIMD extensions 4.1 */
#define CPUID_FEATURE_SSE4_2    _HBit(20) /* Streaming SIMD extensions 4.2 */
#define CPUID_FEATURE_AES       _HBit(25) /* AES instructions */
#define CPUID_FEATURE_OSXSAVE   _HBit(27) /* XGETBV/XSETBV instructions */
#define CPUID_FEATURE_AVX1_0    _HBit(28) /* AVX 1.0 instructions */
#define CPUID_LEAF7_FEATURE_AVX2     _Bit(5)    /* AVX2 Instructions */
#define CPUID_LEAF7_FEATURE_AVX512F  _Bit(16)   /* AVX512F instructions */
#define CPUID_LEAF7_FEATURE_AVX512DQ _Bit(17)   /* AVX512DQ instructions */
#define CPUID_LEAF7_FEATURE_AVX512IFMA _Bit(21) /* AVX512IFMA instructions */
#define CPUID_LEAF7_FEATURE_AVX512CD _Bit(28)   /* AVX512CD instructions */
#define CPUID_LEAF7_FEATURE_AVX512BW _Bit(30)   /* AVX512BW instructions */
#define CPUID_LEAF7_FEATURE_AVX512VL _Bit(31)   /* AVX512VL instructions */
#define CPUID_LEAF7_FEATURE_AVX512VBMI  _HBit(1)/* AVX512VBMI instructions */

extern uint32_t getcpuid();
uint64_t spl_cpuid_features(void);
uint64_t spl_cpuid_leaf7_features(void);

typedef int	processorid_t;

#endif /* _SPL_PROCESSOR_H */
