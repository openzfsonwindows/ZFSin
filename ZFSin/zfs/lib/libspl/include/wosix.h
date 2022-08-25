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
  * Copyright(c) 2019 Jorgen Lundman <lundman@lundman.net>
  */

#ifndef WOSIX_HEADER
#define WOSIX_HEADER

/* Replace all the normal POSIX calls; open, read, write, close, lseek, fstat
 * As we have to use HANDLEs to open devices, we add a shim-layer to handle
 * int fd and the change in underlying API calls.
 * First, include the header that defines them in Windows.
 */
#include <stdio.h>
#include <direct.h>
#include <sys/stat.h>
#include <corecrt_io.h>

#define HTOI(H) ((int)(unsigned __int64)(H))
#define ITOH(I) ((HANDLE)(unsigned __int64)(I))

extern int wosix_fsync(int fd);
extern int wosix_open(const char *path, int oflag, ...);
extern int wosix_close(int fd);
extern int wosix_ioctl(int fd, unsigned long request, void *zc);
extern int wosix_read(int fd, void *data, uint32_t len);
extern int wosix_write(int fd, const void *data, uint32_t len);
extern int wosix_isatty(intptr_t fd);
extern int wosix_mkdir(const char *path, mode_t mode);
extern int wosix_pwrite(int fd, const void *buf, size_t nbyte, off_t offset);
extern int wosix_pread(int fd, void *buf, size_t nbyte, off_t offset);
extern int wosix_stat(char* path, struct _stat64* st);
extern int wosix_fstat(int fd, struct _stat64 *st);
extern int wosix_fstat_blk(int fd, struct _stat64 *st);
extern uint64_t wosix_lseek(int fd, uint64_t offset, int seek);
extern int wosix_fdatasync(int fd);
extern int wosix_ftruncate(int fd, off_t length);
extern int wosix_socketpair(int domain, int type, int protocol, int socket_vector[2]);
extern int wosix_dup2(int fildes, int fildes2);
extern int wosix_pipe(int fildes[2]);

#define wosix_fileno(X) (_get_osfhandle(_fileno((X))))

extern FILE *wosix_fdopen(int fildes, const char *mode);

 /*
 * Thin wrapper for the POSIX IO calls, to translate to HANDLEs
 *
 * Currently it "hopes" that HANDLE value will fit in type "int".
 * This could be improved in future.
 */
#undef  open
#define open	wosix_open
#undef  close
#define close	wosix_close
#undef  ioctl
#define ioctl	wosix_ioctl
#undef  lseek
#define lseek	wosix_lseek
#undef  fsync
#define fsync	wosix_fsync
#undef  read
#define read	wosix_read
#undef  write
#define write	wosix_write
#undef  fileno
#define fileno	wosix_fileno
#undef  isatty
#define isatty	wosix_isatty
#undef  mkdir
#define mkdir	wosix_mkdir
#undef  pread
#define pread	wosix_pread
#define pread64	wosix_pread
#undef  pwrite
#define pwrite	wosix_pwrite
#define pwrite64	wosix_pwrite
#undef  fstat
#define fstat	wosix_fstat
#undef  _fstat64
#define _fstat64	wosix_fstat
#undef  fstat_blk
#define fstat_blk	wosix_fstat_blk
#undef  stat
#define stat	wosix_stat
#undef  fdatasync
#define fdatasync	wosix_fdatasync
#undef  ftruncate
#define ftruncate	wosix_ftruncate
#undef  socketpair
#define socketpair	wosix_socketpair
#undef  fdopen
#define fdopen	wosix_fdopen
#undef  pipe
#define pipe	wosix_pipe

#endif /* WOSIX_HEADER */
