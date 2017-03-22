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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef LIBSPL_RPC_XDR_H
#define	LIBSPL_RPC_XDR_H

#include <sys/types.h>
#include <sys/w32_types.h>
#include <rpc/types.h>
#include <rpc/xdr.h>


enum xdr_op {
	XDR_ENCODE = 0,
	XDR_DECODE = 1,
	XDR_FREE = 2
};

#define BYTES_PER_XDR_UNIT      (4)
#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
                        * BYTES_PER_XDR_UNIT)

typedef struct xdr_bytesrec {
	bool_t xc_is_last_record;
	uint32_t xc_num_avail;
} xdr_bytesrec_t;

typedef bool_t(*xdrproc_t)();

typedef struct {
	enum xdr_op     x_op;           /* operation; fast additional param */
	struct xdr_ops {
		bool_t(*x_getlong)(); /* get a long from underlying stream */
		bool_t(*x_putlong)(); /* put a long to " */
		bool_t(*x_getbytes)(); /* get some bytes from " */
		bool_t(*x_putbytes)(); /* put some bytes to " */
		uint32_t(*x_getpostn)(); /* returns bytes off from beginning */
		bool_t(*x_setpostn)(); /* lets you reposition the stream */
		long *  (*x_inline)();  /* buf quick ptr to buffered data */
		void(*x_destroy)(); /* free privates of this xdr_stream */
	} *x_ops;
	caddr_t         x_public;       /* users' data */
	caddr_t         x_private;      /* pointer to private data */
	caddr_t         x_base;         /* private used for position info */
	int             x_handy;        /* extra private word */
} XDR;



#define XDR_GET_BYTES_AVAIL 1
#define XDR_PEEK        2
#define XDR_SKIPBYTES   3
#define XDR_RDMAGET     4
#define XDR_RDMASET     5

extern bool_t xdr_control(XDR *, int request, void *);


#endif
