/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Unfortunately Windows does not have a #include_next so we
 * renamed this wrapper, and it will have to be manually included
 * after each sys/types.h include
 */


#ifndef _LIBSPL_SYS_W32_TYPES_H
#define	_LIBSPL_SYS_W32_TYPES_H

#include <sys/isa_defs.h>
#include <sys/feature_tests.h>
//#include_next <sys/types.h>
#include <sys/param.h> /* for NBBY */
#include <sys/types32.h>
#include <sys/va_list.h>
#include <sys/timer.h>

#ifndef HAVE_INTTYPES
//#include <inttypes.h>

#ifdef __APPLE__
#include <mach/boolean.h>
#define B_TRUE TRUE
#define B_FALSE FALSE
#else
typedef enum boolean { B_FALSE=0, B_TRUE } boolean_t;
typedef enum boolean bool_t;
#endif

typedef unsigned char	uchar_t;
typedef unsigned short	ushort_t;
typedef unsigned int	uint_t;
typedef unsigned long	ulong_t;

typedef long long	longlong_t;
typedef unsigned long long u_longlong_t;
#endif /* HAVE_INTTYPES */

typedef longlong_t	offset_t;
typedef u_longlong_t	u_offset_t;
typedef u_longlong_t	len_t;
typedef longlong_t	diskaddr_t;

typedef ulong_t		pfn_t;		/* page frame number */
typedef ulong_t		pgcnt_t;	/* number of pages */
typedef long		spgcnt_t;	/* signed number of pages */

typedef longlong_t	hrtime_t;
typedef struct timespec	timestruc_t;
typedef struct timespec timespec_t;

typedef short		pri_t;

typedef int		zoneid_t;
typedef int		projid_t;

typedef int		major_t;
typedef uint_t	minor_t;

typedef ushort_t o_mode_t; /* old file attribute type */
typedef short		index_t;

typedef unsigned long long rlim64_t;

#define F_OK 0
#define W_OK 2
#define R_OK 4

#define MAXPATHLEN MAX_PATH

typedef struct timespec			timestruc_t; /* definition per SVr4 */
typedef struct timespec			timespec_t;


#define strlcpy(D, S, N) strncpy_s((D), (N), (S), _TRUNCATE)
#define strlcat(D, S, N) strncat_s((D), (N), (S), _TRUNCATE)

#if !defined(htonll)
#define htonll(x)       _byteswap_uint64(x)
#endif
#if !defined(ntohll)
#define ntohll(x)       _byteswap_uint64(x)
#endif
#if !defined(ntohl)
#define ntohl(x)       _byteswap_ulong(x)
#endif


/*
 * Definitions remaining from previous partial support for 64-bit file
 * offsets.  This partial support for devices greater than 2gb requires
 * compiler support for long long.
 */
#ifdef _LONG_LONG_LTOH
typedef union {
	offset_t _f;    /* Full 64 bit offset value */
	struct {
		int32_t _l; /* lower 32 bits of offset value */
		int32_t _u; /* upper 32 bits of offset value */
	} _p;
} lloff_t;
#endif

#ifdef _LONG_LONG_HTOL
typedef union {
	offset_t _f;    /* Full 64 bit offset value */
	struct {
		int32_t _u; /* upper 32 bits of offset value */
		int32_t _l; /* lower 32 bits of offset value */
	} _p;
} lloff_t;
#endif

#endif
