/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 by Chunwei Chen. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef _ABD_H
#define	_ABD_H

#include <sys/isa_defs.h>
#include <sys/int_types.h>
#include <sys/debug.h>
#include <sys/refcount.h>
#ifdef _KERNEL
#include <sys/uio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum abd_flags {
	ABD_FLAG_LINEAR	= 1 << 0,	/* is buffer linear (or scattered)? */
	ABD_FLAG_OWNER	= 1 << 1,	/* does it own its data buffers? */
	ABD_FLAG_META	= 1 << 2,	/* does this represent FS metadata? */
	ABD_FLAG_SMALL  = 1 << 3,       /* (APPLE) : abd_alloc() went linear for a sub-chunk size */
	ABD_FLAG_NOMOVE = 1 << 4,       /* (APPLE) : abd_to_buf() called on this abd */
} abd_flags_t;

typedef struct abd {
	abd_flags_t	abd_flags;
	uint_t		abd_size;	/* excludes scattered abd_offset */
	kmutex_t        abd_mutex;
	hrtime_t        abd_create_time;
	struct abd	*abd_parent;
	refcount_t	abd_children;
	union {
		struct abd_scatter {
			uint_t	abd_offset;
			uint_t	abd_chunk_size;
			void	*abd_chunks[];
		} abd_scatter;
		struct abd_linear {
			void	*abd_buf;
		} abd_linear;
	} abd_u;
} abd_t;

typedef int abd_iter_func_t(void *buf, size_t len, void *_private);
typedef int abd_iter_func2_t(void *bufa, void *bufb, size_t len, void *_private);

extern boolean_t zfs_abd_scatter_enabled;

static inline boolean_t
abd_is_linear(abd_t *abd)
{
	return ((abd->abd_flags & ABD_FLAG_LINEAR) != 0);
}

/*
 * Allocations and deallocations
 */

abd_t *abd_alloc(size_t, boolean_t);
abd_t *abd_alloc_linear(size_t, boolean_t);
abd_t *abd_alloc_for_io(size_t, boolean_t);
abd_t *abd_alloc_sametype(abd_t *, size_t);
void abd_free(abd_t *);
abd_t *abd_get_offset(abd_t *, size_t);
abd_t *abd_get_from_buf(void *, size_t);
void abd_put(abd_t *);

/*
 * Conversion to and from a normal buffer
 */

void *abd_to_buf(abd_t *);
void *abd_to_buf_ephemeral(abd_t *);
void *abd_borrow_buf(abd_t *, size_t);
void *abd_borrow_buf_copy(abd_t *, size_t);
void abd_return_buf(abd_t *, void *, size_t);
void abd_return_buf_copy(abd_t *, void *, size_t);
void abd_take_ownership_of_buf(abd_t *, boolean_t);
void abd_release_ownership_of_buf(abd_t *);

/*
 * ABD operations
 */

int abd_iterate_func(abd_t *, size_t, size_t, abd_iter_func_t *, void *);
int abd_iterate_func2(abd_t *, abd_t *, size_t, size_t, size_t,
    abd_iter_func2_t *, void *);
void abd_copy_off(abd_t *, abd_t *, size_t, size_t, size_t);
void abd_copy_from_buf_off(abd_t *, const void *, size_t, size_t);
void abd_copy_to_buf_off(void *, abd_t *, size_t, size_t);
int abd_cmp(abd_t *, abd_t *, size_t);
int abd_cmp_buf_off(abd_t *, const void *, size_t, size_t);
void abd_zero_off(abd_t *, size_t, size_t);

/*
 * Wrappers for calls with offsets of 0
 */

static inline void
abd_copy(abd_t *dabd, abd_t *sabd, size_t size)
{
	ASSERT3P(dabd,!=,NULL);
	ASSERT3P(sabd,!=,NULL);
	ASSERT3P(dabd,!=,sabd);
	if (dabd != sabd) {
		ASSERT3S(dabd->abd_size,==,size);
		ASSERT3S(sabd->abd_size,==,size);
		abd_copy_off(dabd, sabd, 0, 0, size);
	}
}

static inline void
abd_copy_from_buf(abd_t *abd, void *buf, size_t size)
{
	ASSERT3S(abd->abd_size,==,size);
	abd_copy_from_buf_off(abd, buf, 0, size);
}

static inline void
abd_copy_to_buf(void* buf, abd_t *abd, size_t size)
{
	ASSERT3S(abd->abd_size,==,size);
	abd_copy_to_buf_off(buf, abd, 0, size);
}

static inline int
abd_cmp_buf(abd_t *abd, void *buf, size_t size)
{
	ASSERT3S(abd->abd_size,==,size);
	return (abd_cmp_buf_off(abd, buf, 0, size));
}

static inline void
abd_zero(abd_t *abd, size_t size)
{
	ASSERT3S(abd->abd_size,==,size);
	abd_zero_off(abd, 0, size);
}

/*
 * Module lifecycle
 */

void abd_init(void);
void abd_fini(void);

#ifdef __APPLE__
boolean_t abd_try_move(abd_t *);
void abd_kmem_depot_ws_zero(void);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _ABD_H */
