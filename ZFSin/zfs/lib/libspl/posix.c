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
* Copyright (c) 2017 Jorgen Lundman <lundman@lundman.net.  All rights reserved.
*/

#include <sys/types.h>
#include <sys/w32_types.h>

int posix_memalign(void **memptr, uint32_t alignment, uint32_t size)
{
	void *ptr;
	ptr = _aligned_malloc(size, alignment);
	if (ptr == NULL)
		return ENOMEM;
	*memptr = ptr;
	return 0;
}

int fsync(int fd) {
	HANDLE h = (HANDLE)_get_osfhandle(fd); 
	if (!FlushFileBuffers(h)) 
		return EIO; 
	return 0; 
}

