/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (C) 2016 Gvozden Neskovic <neskovic@compeng.uni-frankfurt.de>.
 */

/*
 * USER API:
 *
 * Kernel fpu methods:
 * 	kfpu_begin()
 * 	kfpu_end()
 *
 * SIMD support:
 *
 * Following functions should be called to determine whether CPU feature
 * is supported. All functions are usable in kernel and user space.
 * If a SIMD algorithm is using more than one instruction set
 * all relevant feature test functions should be called.
 *
 * Supported features:
 * 	zfs_sse_available()
 * 	zfs_sse2_available()
 * 	zfs_sse3_available()
 * 	zfs_ssse3_available()
 * 	zfs_sse4_1_available()
 * 	zfs_sse4_2_available()
 *
 * 	zfs_avx_available()
 * 	zfs_avx2_available()
 *
 * 	zfs_bmi1_available()
 * 	zfs_bmi2_available()
 *
 * 	zfs_avx512f_available()
 * 	zfs_avx512cd_available()
 * 	zfs_avx512er_available()
 * 	zfs_avx512pf_available()
 * 	zfs_avx512bw_available()
 * 	zfs_avx512dq_available()
 * 	zfs_avx512vl_available()
 * 	zfs_avx512ifma_available()
 * 	zfs_avx512vbmi_available()
 *
 * NOTE(AVX-512VL):	If using AVX-512 instructions with 128Bit registers
 * 			also add zfs_avx512vl_available() to feature check.
 */

#ifndef _SIMD_X86_H
#define	_SIMD_X86_H

#include <sys/isa_defs.h>
#include <sys/asm_linkage.h>

/* only for __x86 */
#ifdef _WIN32
#ifndef __x86
#define __x86
#endif
#endif


// This file is expected to be used by clang under Windows
// So we have to undo some of the hacks for MSVC++
#ifdef __clang__

#undef __attribute__
#undef aligned
#undef __inline__
#undef __always_inline
#undef __inline

#endif




#if defined(__x86)

#include <sys/types.h>

#if defined(_KERNEL)
#include <intrin.h>
#include <sys/processor.h>
//#include <i386/proc_reg.h>

#ifdef _WIN32
#define xgetbv _xgetbv
#endif

#define	ZFS_ASM_BUG()	break
#define MIN(X,Y) ((X) <= (Y) ? (X) : (Y))


#endif

extern void kfpu_begin(void);
extern void kfpu_end(void);

/*
 * CPUID feature tests for user-space. Linux kernel provides an interface for
 * CPU feature testing.
 */
#if !defined(_KERNEL)

// Don't Forget! This file's userland is NOT in use. See libspl version.
#error "This file is not for userland mode"

#endif /* !defined(_KERNEL) */


/*
 * Detect register set support
 */
static inline boolean_t
__simd_state_enabled(const uint64_t state)
{
	boolean_t has_osxsave;
	uint64_t xcr0;

#if defined(_KERNEL)
	has_osxsave = !!(spl_cpuid_features() & CPUID_FEATURE_OSXSAVE);
#elif !defined(_KERNEL)
	has_osxsave = __cpuid_has_osxsave();
#endif
	if (!has_osxsave)
		return (B_FALSE);

	xcr0 = xgetbv(0);
	return ((xcr0 & state) == state);
}

#define	_XSTATE_SSE_AVX		(0x2 | 0x4)
#define	_XSTATE_AVX512		(0xE0 | _XSTATE_SSE_AVX)

#define	__ymm_enabled() __simd_state_enabled(_XSTATE_SSE_AVX)
#define	__zmm_enabled() __simd_state_enabled(_XSTATE_AVX512)


/*
 * Check if SSE instruction set is available
 */
static inline boolean_t
zfs_sse_available(void)
{
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_SSE);
#elif !defined(_KERNEL)
	return (__cpuid_has_sse());
#endif
}

/*
 * Check if SSE2 instruction set is available
 */
static inline boolean_t
zfs_sse2_available(void)
{
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_SSE2);
#elif !defined(_KERNEL)
	return (__cpuid_has_sse2());
#endif
}

/*
 * Check if SSE3 instruction set is available
 */
static inline boolean_t
zfs_sse3_available(void)
{
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_SSE3);
#elif !defined(_KERNEL)
	return (__cpuid_has_sse3());
#endif
}

/*
 * Check if SSSE3 instruction set is available
 */
static inline boolean_t
zfs_ssse3_available(void)
{
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_SSSE3);
#elif !defined(_KERNEL)
	return (__cpuid_has_ssse3());
#endif
}

/*
 * Check if SSE4.1 instruction set is available
 */
static inline boolean_t
zfs_sse4_1_available(void)
{
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_SSE4_1);
#elif !defined(_KERNEL)
	return (__cpuid_has_sse4_1());
#endif
}

/*
 * Check if SSE4.2 instruction set is available
 */
static inline boolean_t
zfs_sse4_2_available(void)
{
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_SSE4_2);
#elif !defined(_KERNEL)
	return (__cpuid_has_sse4_2());
#endif
}

/*
 * Check if AVX instruction set is available
 */
static inline boolean_t
zfs_avx_available(void)
{
	boolean_t has_avx;
#if defined(_KERNEL)
	return !!(spl_cpuid_features() & CPUID_FEATURE_AVX1_0);
#elif !defined(_KERNEL)
	has_avx = __cpuid_has_avx();
#endif

	return (has_avx && __ymm_enabled());
}

/*
 * Check if AVX2 instruction set is available
 */
static inline boolean_t
zfs_avx2_available(void)
{
	boolean_t has_avx2;
#if defined(_KERNEL)
#if defined(HAVE_AVX2)
	has_avx2 = !!(spl_cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_AVX2);
#else
	has_avx2 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx2 = __cpuid_has_avx2();
#endif

	return (has_avx2 && __ymm_enabled());
}

/*
 * Check if BMI1 instruction set is available
 */
static inline boolean_t
zfs_bmi1_available(void)
{
#if defined(_KERNEL)
#if defined(CPUID_LEAF7_FEATURE_BMI1)
	return !!(spl_cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_BMI1);
#else
	return (B_FALSE);
#endif
#elif !defined(_KERNEL)
	return (__cpuid_has_bmi1());
#endif
}

/*
 * Check if BMI2 instruction set is available
 */
static inline boolean_t
zfs_bmi2_available(void)
{
#if defined(_KERNEL)
#if defined(CPUID_LEAF7_FEATURE_BMI2)
	return !!(spl_cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_BMI2);
#else
	return (B_FALSE);
#endif
#elif !defined(_KERNEL)
	return (__cpuid_has_bmi2());
#endif
}

/*
 * Check if AES instruction set is available
 */
static inline boolean_t
zfs_aes_available(void)
{
#if defined(_KERNEL)
#if defined(HAVE_AES)
	return !!(spl_cpuid_features() & CPUID_FEATURE_AES);
#else
	return (B_FALSE);
#endif
#elif !defined(_KERNEL)
	return (__cpuid_has_aes());
#endif
}

/*
 * Check if PCLMULQDQ instruction set is available
 */
static inline boolean_t
zfs_pclmulqdq_available(void)
{
#if defined(_KERNEL)
#if defined(HAVE_PCLMULQDQ)
	return !!(spl_cpuid_features() & CPUID_FEATURE_PCLMULQDQ);
#else
	return (B_FALSE);
#endif
#elif !defined(_KERNEL)
	return (__cpuid_has_pclmulqdq());
#endif
}

/*
 * AVX-512 family of instruction sets:
 *
 * AVX512F	Foundation
 * AVX512CD	Conflict Detection Instructions
 * AVX512ER	Exponential and Reciprocal Instructions
 * AVX512PF	Prefetch Instructions
 *
 * AVX512BW	Byte and Word Instructions
 * AVX512DQ	Double-word and Quadword Instructions
 * AVX512VL	Vector Length Extensions
 *
 * AVX512IFMA	Integer Fused Multiply Add (Not supported by kernel 4.4)
 * AVX512VBMI	Vector Byte Manipulation Instructions
 */


/* Check if AVX512F instruction set is available */
static inline boolean_t
zfs_avx512f_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512F)
	return !!(spl_cpuid_leaf7_features() & CPUID_LEAF7_FEATURE_AVX512F);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512f();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512CD instruction set is available */
static inline boolean_t
zfs_avx512cd_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512F) && defined(HAVE_AVX512CD)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512CD)) ==
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512CD);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512cd();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512ER instruction set is available */
static inline boolean_t
zfs_avx512er_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512F) && defined(HAVE_AVX512ER) && defined(CPUID_LEAF7_FEATURE_AVX512ER)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512ER)) ==
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512ER);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512er();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512PF instruction set is available */
static inline boolean_t
zfs_avx512pf_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512PF) && defined(HAVE_AVX512F) && defined(CPUID_LEAF7_FEATURE_AVX512PF)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512PF)) ==
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512PF);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512pf();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512BW instruction set is available */
static inline boolean_t
zfs_avx512bw_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512BW) && defined(HAVE_AVX512F)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512BW)) ==
		(CPUID_LEAF7_FEATURE_AVX512F | CPUID_LEAF7_FEATURE_AVX512BW);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512bw();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512DQ instruction set is available */
static inline boolean_t
zfs_avx512dq_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512DQ) && defined(HAVE_AVX512F)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512DQ)) ==
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512DQ);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512dq();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512VL instruction set is available */
static inline boolean_t
zfs_avx512vl_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512VL) && defined(HAVE_AVX512F)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512VL)) ==
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512VL);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512vl();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512IFMA instruction set is available */
static inline boolean_t
zfs_avx512ifma_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512IFMA) && defined(HAVE_AVX512F)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512IFMA)) ==
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512IFMA);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512ifma();
#endif

	return (has_avx512 && __zmm_enabled());
}

/* Check if AVX512VBMI instruction set is available */
static inline boolean_t
zfs_avx512vbmi_available(void)
{
	boolean_t has_avx512 = B_FALSE;

#if defined(_KERNEL)
#if defined(HAVE_AVX512VBMI) && defined(HAVE_AVX512F)
	has_avx512 = (spl_cpuid_leaf7_features() &
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512VBMI)) ==
		(CPUID_LEAF7_FEATURE_AVX512F|CPUID_LEAF7_FEATURE_AVX512VBMI);
#else
	has_avx512 = B_FALSE;
#endif
#elif !defined(_KERNEL)
	has_avx512 = __cpuid_has_avx512f() &&
	    __cpuid_has_avx512vbmi();
#endif

	return (has_avx512 && __zmm_enabled());
}

#endif /* defined(__x86) */

#endif /* _SIMD_X86_H */
