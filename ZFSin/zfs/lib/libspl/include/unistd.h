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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

//#include_next <unistd.h>

#ifndef _LIBSPL_UNISTD_H
#define	_LIBSPL_UNISTD_H

//#include <sys/ioctl.h>

#if !defined(HAVE_ISSETUGID)
#include <sys/types.h>
#include <sys/types32.h>
#define	issetugid() (geteuid() == 0 || getegid() == 0)
#endif

#include <sys/w32_types.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdio.h>

extern int	opterr;
extern int	optind;
extern int	optopt;
extern int	optreset;
extern char	*optarg;

#include <stdarg.h>
#include <io.h>
#include <direct.h>

typedef void* HANDLE;

size_t strlcpy(register char* s, register const char* t, register size_t n);

size_t strlcat(register char* s, register const char* t, register size_t n);

ssize_t getline(char** linep, size_t *linecapp, FILE* stream);

int pread_win(HANDLE h, void* buf, size_t nbyte, off_t offset);
char* realpath(const char* file_name, char* resolved_name);
int usleep(__int64 usec);
int vasprintf(char** strp, const char* fmt, va_list ap);
int asprintf(char** strp, const char* fmt, ...);
int strncasecmp(char* s1, char* s2, size_t n);
int readlink(const char* path, char* buf, size_t bufsize);
const char* getexecname(void);
uint64_t geteuid(void);

struct zfs_cmd;
int64_t gethrtime(void);
int gettimeofday(struct timeval* tp, struct timezone* tzp);
void flockfile(FILE* file);
void funlockfile(FILE* file);
unsigned long gethostid(void);
char* strndup(char* src, size_t size);
int setrlimit(int resource, const struct rlimit* rlp);

struct group* getgrgid(uint64_t gid);
struct passwd* getpwuid(uint64_t uid);
void syslog(int priority, const char* message, ...);
void closelog(void);
int statfs(const char* path, struct statfs* buf);

int unmount(const char* dir, int flags);

#endif /* _LIBSPL_UNISTD_H */
