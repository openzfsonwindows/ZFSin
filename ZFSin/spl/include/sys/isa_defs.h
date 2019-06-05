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
 * Copyright 2008 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */



#ifndef	_SPL_ISA_DEFS_H
#define	_SPL_ISA_DEFS_H

/* x86_64 arch specific defines */
#if defined(__x86_64) || defined(__x86_64__)

#if !defined(__x86_64)
#define __x86_64
#endif

#if !defined(__amd64)
#define __amd64
#endif

#if !defined(__x86)
#define __x86
#endif

#if !defined(_LP64)
#define _LP64
#endif

/* i386 arch specific defines */
#elif defined(__i386) || defined(__i386__)

#if !defined(__i386)
#define __i386
#endif

#if !defined(__x86)
#define __x86
#endif

#if !defined(_ILP32)
#define _ILP32
#endif

/* powerpc (ppc64) arch specific defines */
#elif defined(__powerpc) || defined(__powerpc__)

#if !defined(__powerpc)
#define __powerpc
#endif

#if !defined(__powerpc__)
#define __powerpc__
#endif

#if !defined(_LP64)
#define _LP64
#endif

/* arm arch specific defines */
#elif defined(__arm) || defined(__arm__)

#if !defined(__arm)
#define __arm
#endif

#if !defined(__arm__)
#define __arm__
#endif

#if defined(__ARMEL__)
#define _LITTLE_ENDIAN
#else
#define _BIG_ENDIAN
#endif

#else /* Currently only x86_64, i386, arm, and powerpc arches supported */
#error "Unsupported ISA type"
#endif

#if defined(_ILP32) && defined(_LP64)
#error "Both _ILP32 and _LP64 are defined"
#endif

#include <sys/byteorder.h>

#if defined(__LITTLE_ENDIAN) && !defined(_LITTLE_ENDIAN)
#define _LITTLE_ENDIAN __LITTLE_ENDIAN
#endif

#if defined(__BIG_ENDIAN) && !defined(_BIG_ENDIAN)
#define _BIG_ENDIAN __BIG_ENDIAN
#endif

#if defined(_LITTLE_ENDIAN) && defined(_BIG_ENDIAN)
#error "Both _LITTLE_ENDIAN and _BIG_ENDIAN are defined"
#endif

#if !defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#error "Neither _LITTLE_ENDIAN or _BIG_ENDIAN are defined"
#endif


#ifdef _WIN32
	/*
	 * Ordinarily, configure.ac will work out the toolchain abilities of the compiler,
	 * but we will list them statically per version of LLVM used.
	 */
/* Define if host toolchain supports AES */
#define HAVE_AES 1
/* Define if host toolchain supports AVX */
#define HAVE_AVX 1
#define HAVE_AVX2 1
#define HAVE_AVX512BW 1
#define HAVE_AVX512CD 1
#define HAVE_AVX512DQ 1
#define HAVE_AVX512ER 1
#define HAVE_AVX512F 1
#define HAVE_AVX512IFMA 1
#define HAVE_AVX512PF 1
#define HAVE_AVX512VBMI 1
#define HAVE_AVX512VL 1
#define HAVE_SSE 1
#define HAVE_SSE2 1
#define HAVE_SSE3 1
#define HAVE_SSE4_1 1
#define HAVE_SSE4_2 1
#define HAVE_SSSE3 1
#define	HAVE_PCLMULQDQ 1
#endif // WIN32

#endif	/* _SPL_ISA_DEFS_H */
