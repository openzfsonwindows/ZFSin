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
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#include <sys/types.h>
#include <sys/types32.h>
#include <sys/w32_types.h>
#include <time.h>
#include <io.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mntent.h>
#include <fcntl.h>
#include <sys/zfs_ioctl.h>
#include <WinSock2.h>
#include <pthread.h>

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

struct passwd *getpwnam(const char *login)
{
	return NULL;
}

struct passwd *getgrnam(const char *group)
{
	return NULL;
}

struct tm *localtime_r(const time_t *clock, struct tm *result)
{
	if (_localtime64_s(result, clock) == 0)
		return result;
	return NULL;
}

char *
strsep(char **stringp, const char *delim) 
{
	char *s;
	const char *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);
	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}
	/* NOTREACHED */
}

char *realpath(const char *file_name, char *resolved_name)
{
	DWORD ret;
	// If resolved_name is NULL, we allocate space. Otherwise we assume
	// PATH_MAX - but pretty sure this style isn't used in ZFS
	if (resolved_name == NULL)
		resolved_name = malloc(PATH_MAX);
	if (resolved_name == NULL)
		return NULL;
	ret = GetFullPathName(file_name, PATH_MAX, resolved_name, NULL);
	if (ret == 0)
		return NULL;

	return resolved_name;
}

ssize_t pread(int fd, void *buf, uint32_t nbyte, off_t offset)
{
	uint64_t off;
	ssize_t red;

	off = _lseek(fd, 0, SEEK_CUR);
	if (_lseek(fd, offset, SEEK_SET) != offset)
		return -1;

	red = read(fd, buf, nbyte);

	_lseek(fd, off, SEEK_SET);

	return red;
}

ssize_t pwrite(int fd, const void *buf, uint32_t nbyte, off_t offset)
{
	uint64_t off;
	ssize_t wrote;

	off = _lseek(fd, 0, SEEK_CUR);
	if (_lseek(fd, offset, SEEK_SET) != offset)
		return -1;

	wrote = write(fd, buf, nbyte);

	_lseek(fd, off, SEEK_SET);

	return wrote;
}


int fstat_blk(int fd, struct _stat64 *st)
{
	DISK_GEOMETRY_EX geometry_ex;
	HANDLE handle;
	DWORD len;

	handle = _get_osfhandle(fd);
	if (!DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
		&geometry_ex, sizeof(geometry_ex), &len, NULL))
		return -1;

	st->st_size = (diskaddr_t)geometry_ex.DiskSize.QuadPart;

	return (0);
}

int statfs(const char *path, struct statfs *buf)
{
	ULARGE_INTEGER lpFreeBytesAvailable;
	ULARGE_INTEGER lpTotalNumberOfBytes;
	ULARGE_INTEGER lpTotalNumberOfFreeBytes;
	uint64_t lbsize;

	if (GetDiskFreeSpaceEx(path,
		&lpFreeBytesAvailable,
		&lpTotalNumberOfBytes,
		&lpTotalNumberOfFreeBytes))
		return -1;

	DISK_GEOMETRY_EX geometry_ex;
	HANDLE handle;
	DWORD len;

	int fd = open(path, O_RDONLY | O_BINARY);
	handle = _get_osfhandle(fd);
	if (!DeviceIoControl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
		&geometry_ex, sizeof(geometry_ex), &len, NULL))
		return -1;
	close(fd);
	lbsize = (uint_t)geometry_ex.Geometry.BytesPerSector;

	buf->f_bsize = lbsize;
	buf->f_blocks = lpTotalNumberOfBytes.QuadPart / lbsize;
	buf->f_bfree = lpTotalNumberOfFreeBytes.QuadPart / lbsize;
	buf->f_bavail = lpTotalNumberOfFreeBytes.QuadPart / lbsize;
	buf->f_type = 0;
	strcpy(buf->f_fstypename, "fixme");
	strcpy(buf->f_mntonname, "fixme_to");
	strcpy(buf->f_mntfromname, "fixme_from");

	return 0;
}


static const char letters[] =
"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
int
mkstemp(char *tmpl)
{
	int len;
	char *XXXXXX;
	static unsigned long long value;
	unsigned long long random_time_bits;
	unsigned int count;
	int fd = -1;
	int save_errno = errno;

#define ATTEMPTS_MIN (62 * 62 * 62)

#if ATTEMPTS_MIN < TMP_MAX
	unsigned int attempts = TMP_MAX;
#else
	unsigned int attempts = ATTEMPTS_MIN;
#endif

	len = strlen(tmpl);
	if (len < 6 || strcmp(&tmpl[len - 6], "XXXXXX"))
	{
		errno = EINVAL;
		return -1;
	}

	XXXXXX = &tmpl[len - 6];

	{
		SYSTEMTIME      stNow;
		FILETIME ftNow;

		// get system time
		GetSystemTime(&stNow);
		stNow.wMilliseconds = 500;
		if (!SystemTimeToFileTime(&stNow, &ftNow))
		{
			errno = -1;
			return -1;
		}

		random_time_bits = (((unsigned long long)ftNow.dwHighDateTime << 32)
			| (unsigned long long)ftNow.dwLowDateTime);
	}
	value += random_time_bits ^ (unsigned long long)GetCurrentThreadId();

	for (count = 0; count < attempts; value += 7777, ++count)
	{
		unsigned long long v = value;

		/* Fill in the random bits.  */
		XXXXXX[0] = letters[v % 62];
		v /= 62;
		XXXXXX[1] = letters[v % 62];
		v /= 62;
		XXXXXX[2] = letters[v % 62];
		v /= 62;
		XXXXXX[3] = letters[v % 62];
		v /= 62;
		XXXXXX[4] = letters[v % 62];
		v /= 62;
		XXXXXX[5] = letters[v % 62];

		fd = open(tmpl, O_RDWR | O_CREAT | O_EXCL, _S_IREAD | _S_IWRITE);
		if (fd >= 0)
		{
			errno = save_errno;
			return fd;
		}
		else if (errno != EEXIST)
			return -1;
	}

	/* We got out of the loop because we ran out of combinations to try.  */
	errno = EEXIST;
	return -1;
}


int readlink(const char *path, char *buf, size_t bufsize)
{
	return -1;
}

int usleep(__int64 usec)
{
	HANDLE timer;
	LARGE_INTEGER ft;

	ft.QuadPart = -(10 * usec); // Convert to 100 nanosecond interval, negative value indicates relative time

	timer = CreateWaitableTimer(NULL, TRUE, NULL);
	SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
	WaitForSingleObject(timer, INFINITE);
	CloseHandle(timer);
}

boolean_t nanosleep(int64_t ns) 
{
	/* Declarations */
	HANDLE timer;	/* Timer handle */
	LARGE_INTEGER li;	/* Time defintion */
						/* Create timer */
	if (!(timer = CreateWaitableTimer(NULL, TRUE, NULL)))
		return FALSE;
	/* Set timer properties */
	li.QuadPart = -ns;
	if (!SetWaitableTimer(timer, &li, 0, NULL, NULL, FALSE)) {
		CloseHandle(timer);
		return FALSE;
	}
	/* Start & wait for timer */
	WaitForSingleObject(timer, INFINITE);
	/* Clean resources */
	CloseHandle(timer);
	/* Slept without problems */
	return TRUE;
}

int strncasecmp(char *s1, char *s2, uint32_t n)
{
	if (n == 0)
		return 0;

	while (n-- != 0 && tolower(*s1) == tolower(*s2))
	{
		if (n == 0 || *s1 == '\0' || *s2 == '\0')
			break;
		s1++;
		s2++;
	}

	return tolower(*(unsigned char *)s1) - tolower(*(unsigned char *)s2);
}

#define DIRNAME         0
#define BASENAME        1

#define M_FSDELIM(c)    ((c)=='/'||(c)=='\\')
#define M_DRDELIM(c)    (0)

static char curdir[] = ".";
static char *
basedir(char *arg, int type)
{
	register char *cp, *path;

	if (arg == (char *)0 || *arg == '\0' ||
		(*arg == '.' && (arg[1] == '\0' ||
		(type == DIRNAME && arg[1] == '.' && arg[2] == '\0'))))

		return curdir;  /* arg NULL, empty, ".", or ".." in DIRNAME */

	if (M_DRDELIM(arg[1]))  /* drive-specified pathnames */
		path = arg + 2;
	else
		path = arg;

	if (path[1] == '\0'&&M_FSDELIM(*path))    /* "/", or drive analog */
		return arg;

	cp = strchr(path, '\0');
	cp--;

	while (cp != path && M_FSDELIM(*cp))
		*(cp--) = '\0';

	for (;cp>path && !M_FSDELIM(*cp); cp--)
		;

	if (!M_FSDELIM(*cp))
		if (type == DIRNAME && path != arg) {
			*path = '\0';
			return arg;     /* curdir on the specified drive */
		}
		else
			return (type == DIRNAME) ? curdir : path;
	else if (cp == path && type == DIRNAME) {
		cp[1] = '\0';
		return arg;             /* root directory involved */
	}
	else if (cp == path && cp[1] == '\0')
		return(arg);
	else if (type == BASENAME)
		return ++cp;
	*cp = '\0';
	return arg;
}

char *
dirname(char *arg)
{
	return(basedir(arg, DIRNAME));
}

char *
basename(char *arg)
{
	return(basedir(arg, BASENAME));
}


int ioctl(HANDLE hDevice, int request, zfs_cmd_t *zc)
{
	int error;
	//HANDLE hDevice;
	ULONG bytesReturned;

	//hDevice = _get_osfhandle(fd);
#if 0
	fprintf(stderr, "calling ioctl on 0x%x (raw 0x%x) struct size %d in %p:%d out %p:%d\n", 
		(request&0x2ffc) >> 2, request,
		sizeof(zfs_cmd_t),
		zc->zc_nvlist_src, zc->zc_nvlist_src_size,
		zc->zc_nvlist_dst, zc->zc_nvlist_dst_size
		); fflush(stderr);
	strcpy(zc->zc_name, "thisisatest");
	zc->zc_dev = 0x12345678;
	for (int x = 0; x < 16; x++)
		fprintf(stderr, "%02x ", ((unsigned char *)zc)[x]);
	fprintf(stderr, "\n");
	fflush(stderr);
#endif
	error = DeviceIoControl(hDevice,
		(DWORD)request,
		zc,
		(DWORD)sizeof(zfs_cmd_t),
		zc,
		(DWORD)sizeof(zfs_cmd_t),
		&bytesReturned,
		NULL
	);

	if (error == 0)
		error = GetLastError();
	else
		error = 0;

	fprintf(stderr, "    (ioctl 0x%x status %d bytes %ld)\n", (request & 0x2ffc) >> 2, error, bytesReturned); fflush(stderr);
#if 0
	for (int x = 0; x < 16; x++)
		fprintf(stderr, "%02x ", ((unsigned char *)zc)[x]);
	fprintf(stderr, "\n");
	fflush(stderr);
	fprintf(stderr, "returned ioctl on 0x%x (raw 0x%x) struct size %d in %p:%d out %p:%d\n",
		(request & 0x2ffc) >> 2, request,
		sizeof(zfs_cmd_t),
		zc->zc_nvlist_src, zc->zc_nvlist_src_size,
		zc->zc_nvlist_dst, zc->zc_nvlist_dst_size
	); fflush(stderr);
#endif

	return error;
}


int vasprintf(char **strp, const char *fmt, va_list ap)
{
	int r = -1, size;
	
	size = _vscprintf(fmt, ap);

	if ((size >= 0) && (size < INT_MAX)) {
		*strp = (char *)malloc(size + 1);
		if (*strp) {
			r = vsnprintf(*strp, size + 1, fmt, ap);
			if ((r < 0) || (r > size)) {
				r = -1;
				free(*strp);
			}
		}
	} else {
		*strp = 0; 
	}

	return(r);
}


int asprintf(char **strp, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = vasprintf(strp, fmt, ap);
	va_end(ap);
	return(r);
}


int gettimeofday(struct timeval * tp, struct timezone * tzp)
{
	// Note: some broken versions only have 8 trailing zero's, the correct epoch has 9 trailing zero's
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tp->tv_sec = (long)((time - EPOCH) / 10000000L);
	tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}


void flockfile(FILE *file)
{
}

void funlockfile(FILE *file)
{
}

long gethostid(void)
{
	char szVolName[MAX_PATH];
	char szFileSysName[80];
	DWORD dwSerialNumber;
	DWORD dwMaxComponentLen;
	DWORD dwFileSysFlags;


	GetVolumeInformation("C:\\", szVolName, MAX_PATH,
		&dwSerialNumber, &dwMaxComponentLen,
		&dwFileSysFlags, szFileSysName, 80);
	return dwSerialNumber;
}

uid_t geteuid(void)
{
	return 0; // woah, root?
}

struct passwd *getpwuid(uid_t uid)
{
	return NULL;
}

const char *ctime_r(char *buffer, size_t bufsize, time_t cur_time)
{
	errno_t e = ctime_s(buffer, bufsize, cur_time);
	return buffer;
}