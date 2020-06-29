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
 *
 * Copyright (C) 2017 Jorgen Lundman <lundman@lundman.net>
 *
 */

#include <sys/kobj.h>
#include <spl-debug.h>
#include <sys/vnode.h>
//#include <sys/malloc.h>
//#include <libkern/libkern.h>

#include <Trace.h>

struct _buf *
kobj_open_file(char *name)
{
    struct vnode *vp=NULL;
 //   vfs_context_t vctx;
    struct _buf *file;
    int error=0;

 //   vctx = vfs_context_create((vfs_context_t)0);
//    error = vnode_open(name, 0, 0, 0, &vp, vctx);
   // (void) vfs_context_rele(vctx);

    if (error) {
        TraceEvent(TRACE_ERROR, "kobj_open_file: \"%s\", err %d from vnode_open\n", name ? name : "", error);

        return ((struct _buf *)-1);
    }
    file = (struct _buf *)kmem_alloc(sizeof (struct _buf *), KM_SLEEP);
    file->_fd = (intptr_t)vp;

    return (file);
}

void
kobj_close_file(struct _buf *file)
{
//    vfs_context_t vctx;

    //vctx = vfs_context_create((vfs_context_t)0);
   // (void) vnode_close((struct vnode *)file->_fd, 0, vctx);
    //(void) vfs_context_rele(vctx);

    kmem_free(file, sizeof (struct _buf));
}

int
kobj_fstat(struct vnode *vp, struct bootstat *buf)
{
//    struct vnode_attr vattr;
//    vfs_context_t vctx;
    int error=0;

    if (buf == NULL)
        return (-1);

  //  VATTR_INIT(&vattr);
 //   VATTR_WANTED(&vattr, va_mode);
 //   VATTR_WANTED(&vattr, va_data_size);
//    vattr.va_mode = 0;
//    vattr.va_data_size = 0;

    //vctx = vfs_context_create((vfs_context_t)0);
    //error = vnode_getattr(vp, &vattr, vctx);
    //(void) vfs_context_rele(vctx);

    if (error == 0) {
        //buf->st_mode = (uint32_t)vattr.va_mode;
  //      buf->st_size = vattr.va_data_size;
    }
    return (error);
}

int
kobj_read_file(struct _buf *file, char *buf, ssize_t size, offset_t off)
{
    struct vnode *vp = (struct vnode *)file->_fd;
    //vfs_context_t vctx;
    uio_t *auio;
    int count=0;
    int error;

    //vctx = vfs_context_create((vfs_context_t)0);
    //auio = uio_create(1, 0, UIO_SYSSPACE32, UIO_READ);
    //uio_reset(auio, off, UIO_SYSSPACE32, UIO_READ);
    //uio_addiov(auio, (uintptr_t)buf, size);

    //error = VNOP_READ(vp, auio, 0, vctx);

  //  if (error)
 //       count = -1;
 //   else
 //       count = size - uio_resid(auio);

 //   uio_free(auio);
   // (void) vfs_context_rele(vctx);

    return (count);
}

/*
 * Get the file size.
 *
 * Before root is mounted, files are compressed in the boot_archive ramdisk
 * (in the memory). kobj_fstat would return the compressed file size.
 * In order to get the uncompressed file size, read the file to the end and
 * count its size.
 */
int
kobj_get_filesize(struct _buf *file, uint64_t *size)
{
    /*
     * In OSX, the root will always be mounted, so we can
     * just use kobj_fstat to stat the file
     */
    struct bootstat bst;

    if (kobj_fstat((struct vnode *)file->_fd, &bst) != 0)
        return (EIO);
    *size = bst.st_size;
    return (0);
}
