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
	if (localtime_s(result, clock) == 0)
		return result;
	// To avoid the ASSERT and abort(), make tm be something valid
	memset(result, 0, sizeof(*result));
	result->tm_mday = 1;
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

int pread(int fd, void *buf, uint32_t nbyte, off_t offset)
{
	uint64_t off;
	int red;

	off = _lseek(fd, 0, SEEK_CUR);
	if (_lseek(fd, offset, SEEK_SET) != offset)
		return -1;

	red = read(fd, buf, nbyte);

	_lseek(fd, off, SEEK_SET);

	return red;
}

int pread_win(HANDLE h, void *buf, uint32_t nbyte, off_t offset)
{
	uint64_t off;
	DWORD red;
	LARGE_INTEGER large;
	LARGE_INTEGER lnew;

	// This code does all seeks based on "current" so we can pre-seek to offset start

	// Find current position
	large.QuadPart = 0;
	SetFilePointerEx(h, large, &lnew, FILE_CURRENT);

	// Seek to place to read
	large.QuadPart = offset;
	SetFilePointerEx(h, large, NULL, FILE_CURRENT);

	// Read
	if (!ReadFile(h, buf, nbyte, &red, NULL))
		red = -GetLastError();

	// Restore position
	SetFilePointerEx(h, lnew, NULL, FILE_BEGIN);

	return red;
}

int pwrite(HANDLE h, const void *buf, uint32_t nbyte, off_t offset)
{
	uint64_t off;
	DWORD wrote;
	LARGE_INTEGER large;
	LARGE_INTEGER lnew;

	// This code does all seeks based on "current" so we can pre-seek to offset start

	// Find current position
	large.QuadPart = 0;
	SetFilePointerEx(h, large, &lnew, FILE_CURRENT);

	// Seek to place to read
	large.QuadPart = offset;
	SetFilePointerEx(h, large, NULL, FILE_CURRENT);

	// Read
	if (!WriteFile(h, buf, nbyte, &wrote, NULL))
		wrote = -GetLastError();

	// Restore position
	SetFilePointerEx(h, lnew, NULL, FILE_BEGIN);

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

#if 1
	if (GetDiskFreeSpaceEx(path,
		&lpFreeBytesAvailable,
		&lpTotalNumberOfBytes,
		&lpTotalNumberOfFreeBytes))
		return -1;
#endif

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

char* getIoctlAsString(int cmdNo) {
	switch (cmdNo) {
		case 0x800: return "ZFS_IOC_FIRST";
		case 0x801: return "ZFS_IOC_POOL_DESTROY";
		case 0x802: return "ZFS_IOC_POOL_IMPORT";
		case 0x803: return "ZFS_IOC_POOL_EXPORT";
		case 0x804: return "ZFS_IOC_POOL_CONFIGS";
		case 0x805: return "ZFS_IOC_POOL_STATS";
		case 0x806: return "ZFS_IOC_POOL_TRYIMPORT";
		case 0x807: return "ZFS_IOC_POOL_SCAN";
		case 0x808: return "ZFS_IOC_POOL_FREEZE";
		case 0x809: return "ZFS_IOC_POOL_UPGRADE";
		case 0x80a: return "ZFS_IOC_POOL_GET_HISTORY";
		case 0x80b: return "ZFS_IOC_VDEV_ADD";
		case 0x80c: return "ZFS_IOC_VDEV_REMOVE";
		case 0x80d: return "ZFS_IOC_VDEV_SET_STATE";
		case 0x80e: return "ZFS_IOC_VDEV_ATTACH";
		case 0x80f: return "ZFS_IOC_VDEV_DETACH";
		case 0x810: return "ZFS_IOC_VDEV_SETPATH";
		case 0x811: return "ZFS_IOC_VDEV_SETFRU";
		case 0x812: return "ZFS_IOC_OBJSET_STATS";
		case 0x813: return "ZFS_IOC_OBJSET_ZPLPROPS";
		case 0x814: return "ZFS_IOC_DATASET_LIST_NEXT";
		case 0x815: return "ZFS_IOC_SNAPSHOT_LIST_NEXT";
		case 0x816: return "ZFS_IOC_SET_PROP";
		case 0x817: return "ZFS_IOC_CREATE";
		case 0x818: return "ZFS_IOC_DESTROY";
		case 0x819: return "ZFS_IOC_ROLLBACK";
		case 0x81a: return "ZFS_IOC_RENAME";
		case 0x81b: return "ZFS_IOC_RECV";
		case 0x81c: return "ZFS_IOC_SEND";
		case 0x81d: return "ZFS_IOC_INJECT_FAULT";
		case 0x81e: return "ZFS_IOC_CLEAR_FAULT";
		case 0x81f: return "ZFS_IOC_INJECT_LIST_NEXT";
		case 0x820: return "ZFS_IOC_ERROR_LOG";
		case 0x821: return "ZFS_IOC_CLEAR";
		case 0x822: return "ZFS_IOC_PROMOTE";
		case 0x823: return "ZFS_IOC_SNAPSHOT";
		case 0x824: return "ZFS_IOC_DSOBJ_TO_DSNAME";
		case 0x825: return "ZFS_IOC_OBJ_TO_PATH";
		case 0x826: return "ZFS_IOC_POOL_SET_PROPS";
		case 0x827: return "ZFS_IOC_POOL_GET_PROPS";
		case 0x828: return "ZFS_IOC_SET_FSACL";
		case 0x829: return "ZFS_IOC_GET_FSACL";
		case 0x82a: return "ZFS_IOC_SHARE";
		case 0x82b: return "ZFS_IOC_INHERIT_PROP";
		case 0x82c: return "ZFS_IOC_SMB_ACL";
		case 0x82d: return "ZFS_IOC_USERSPACE_ONE";
		case 0x82e: return "ZFS_IOC_USERSPACE_MANY";
		case 0x82f: return "ZFS_IOC_USERSPACE_UPGRADE";
		case 0x830: return "ZFS_IOC_HOLD";
		case 0x831: return "ZFS_IOC_RELEASE";
		case 0x832: return "ZFS_IOC_GET_HOLDS";
		case 0x833: return "ZFS_IOC_OBJSET_RECVD_PROPS";
		case 0x834: return "ZFS_IOC_VDEV_SPLIT";
		case 0x835: return "ZFS_IOC_NEXT_OBJ";
		case 0x836: return "ZFS_IOC_DIFF";
		case 0x837: return "ZFS_IOC_TMP_SNAPSHOT";
		case 0x838: return "ZFS_IOC_OBJ_TO_STATS";
		case 0x839: return "ZFS_IOC_SPACE_WRITTEN";
		case 0x83a: return "ZFS_IOC_SPACE_SNAPS";
		case 0x83b: return "ZFS_IOC_DESTROY_SNAPS";
		case 0x83c: return "ZFS_IOC_POOL_REGUID";
		case 0x83d: return "ZFS_IOC_POOL_REOPEN";
		case 0x83e: return "ZFS_IOC_SEND_PROGRESS";
		case 0x83f: return "ZFS_IOC_LOG_HISTORY";
		case 0x840: return "ZFS_IOC_SEND_NEW";
		case 0x841: return "ZFS_IOC_SEND_SPACE";
		case 0x842: return "ZFS_IOC_CLONE";
		case 0x843: return "ZFS_IOC_BOOKMARK";
		case 0x844: return "ZFS_IOC_GET_BOOKMARKS";
		case 0x845: return "ZFS_IOC_DESTROY_BOOKMARKS";
		case 0x846: return "ZFS_IOC_LOAD_KEY";
		case 0x847: return "ZFS_IOC_UNLOAD_KEY";
		case 0x848: return "ZFS_IOC_CHANGE_KEY";
		case 0x849: return "ZFS_IOC_REMAP";
		case 0x84a: return "ZFS_IOC_POOL_CHECKPOINT";
		case 0x84b: return "ZFS_IOC_POOL_DISCARD_CHECKPOINT";
		case 0x84c: return "ZFS_IOC_POOL_INITIALIZE";
		case 0x84d: return "ZFS_IOC_POOL_SYNC";
		case 0x84e: return "ZFS_IOC_CHANNEL_PROGRAM";

		case 0x880: return "ZFS_IOC_EVENTS_NEXT";
		case 0x881: return "ZFS_IOC_EVENTS_CLEAR";
		case 0x882: return "ZFS_IOC_EVENTS_SEEK";

		case 0x8E0: return "ZFS_IOC_MOUNT";
		case 0x8E1: return "ZFS_IOC_UNMOUNT";
		case 0x8E2: return "ZFS_IOC_UNREGISTER_FS";

		case 0x8E3: return "ZFS_IOC_LAST";
		default: return "unkown";
	}
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
		error = zc->zc_ioc_error;
	
#ifdef DEBUG
	fprintf(stderr, "    (ioctl 0x%x (%s) status %d bytes %ld)\n", (request & 0x2ffc) >> 2, getIoctlAsString((request & 0x2ffc) >> 2), error, bytesReturned); fflush(stderr);
#endif
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

const char *win_ctime_r(char *buffer, uint32_t bufsize, time_t cur_time)
{
	errno_t e = ctime_s(buffer, bufsize, cur_time);
	return buffer;
}

uint64_t GetFileDriveSize(HANDLE h)
{
	LARGE_INTEGER large;

	if (GetFileSizeEx(h, &large))
		return large.QuadPart;

	DISK_GEOMETRY_EX geometry_ex;
	DWORD len;
	if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
		&geometry_ex, sizeof(geometry_ex), &len, NULL))
		return geometry_ex.DiskSize.QuadPart;


	PARTITION_INFORMATION partInfo;
	DWORD retcount = 0;

	if (DeviceIoControl(h,
		IOCTL_DISK_GET_PARTITION_INFO,
		(LPVOID)NULL,
		(DWORD)0,
		(LPVOID)&partInfo,
		sizeof(partInfo),
		&retcount,
		(LPOVERLAPPED)NULL)) {
		return partInfo.PartitionLength.QuadPart;
	}
	return 0;
}


void
openlog(const char *ident, int logopt, int facility)
{

}

void
syslog(int priority, const char *message, ... )
{

}

void
closelog(void)
{

}

int
pipe(int fildes[2])
{
	return -1;
}

struct group *
	getgrgid(gid_t gid)
{
	return NULL;
}

int
unmount(const char *dir, int flags)
{
	return -1;
}

int socketpair(int *sv)
{
	int temp, s1, s2, result;
	struct sockaddr_in saddr;
	int nameLen;
	unsigned long option_arg = 1;

	nameLen = sizeof(saddr);

	/* ignore address family for now; just stay with AF_INET */
	temp = socket(AF_INET, SOCK_STREAM, 0);
	if (temp == INVALID_SOCKET) return -1;

	setsockopt(temp, SOL_SOCKET, SO_REUSEADDR, (void *)&option_arg,
		sizeof(option_arg));

	/* We *SHOULD* choose the correct sockaddr structure based
	on the address family requested... */
	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	saddr.sin_port = 0; // give me a port

	result = bind(temp, (struct sockaddr *)&saddr, nameLen);
	if (result == SOCKET_ERROR) {
		errno = WSAGetLastError();
		closesocket(temp);
		return -2;
	}

	// Don't care about error here, the connect will fail instead
	listen(temp, 1);

	// Fetch out the port that was given to us.
	nameLen = sizeof(struct sockaddr_in);

	result = getsockname(temp, (struct sockaddr *)&saddr, &nameLen);

	if (result == INVALID_SOCKET) {
		closesocket(temp);
		return -4; /* error case */
	}

	s1 = socket(AF_INET, SOCK_STREAM, 0);
	if (s1 == INVALID_SOCKET) {
		closesocket(temp);
		return -5;
	}

	nameLen = sizeof(struct sockaddr_in);

	result = connect(s1, (struct sockaddr *)&saddr, nameLen);

	if (result == INVALID_SOCKET) {
		closesocket(temp);
		closesocket(s1);
		return -6; /* error case */
	}

	s2 = accept(temp, NULL, NULL);

	closesocket(temp);

	if (s2 == INVALID_SOCKET) {
		closesocket(s1);
		return -7;
	}

	sv[0] = s1; sv[1] = s2;

	if ((sv[0] < 0) || (sv[1] < 0)) return -8;

	return 0;  /* normal case */
}

extern uint32_t
strlcpy(register char* s, register const char* t, register uint32_t n)
{
	const char*     o = t;

	if (n)
		do
		{
			if (!--n)
			{
				*s = 0;
				break;
			}
		} while (*s++ = *t++);
		if (!n)
			while (*t++);
		return t - o - 1;
}

extern uint32_t
strlcat(register char* s, register const char* t, register uint32_t n)
{
	register size_t m;
	const char*     o = t;

	if (m = n)
	{
		while (n && *s)
		{
			n--;
			s++;
		}
		m -= n;
		if (n)
			do
			{
				if (!--n)
				{
					*s = 0;
					break;
				}
			} while (*s++ = *t++);
		else
			*s = 0;
	}
	if (!n)
		while (*t++);
	return (t - o) + m - 1;
}

char *strndup(char *src, int size)
{
	char *r = _strdup(src);
	if (r) {
		r[size] = 0;
	}
	return r;
}

int win_isatty(HANDLE h) 
{ 
	DWORD mode;
	int ret;
#if 0
	const unsigned long bufSize = sizeof(DWORD) + MAX_PATH * sizeof(WCHAR);
	BYTE buf[sizeof(DWORD) + MAX_PATH * sizeof(WCHAR)];
	PFILE_NAME_INFO pfni = (PFILE_NAME_INFO)buf;

	if (!GetFileInformationByHandleEx(h, FileNameInfo, buf, bufSize)) {
		return 0;
	}

	PWSTR fn = pfni->FileName;
	fn[pfni->FileNameLength] = L'\0';

	ret = ((wcsstr(fn, L"\\cygwin-") || wcsstr(fn, L"\\msys-")) &&
		wcsstr(fn, L"-pty") && wcsstr(fn, L"-master"));

	//printf("ret %d Got name as '%S'\n", ret, fn); fflush(stdout);
	return ret;
#else

	ret = ((GetFileType(h) & ~FILE_TYPE_REMOTE) == FILE_TYPE_CHAR);

#endif
	//fprintf(stderr, "%s: return %d\r\n", __func__, ret);
	//fflush(stderr);
	return ret;
}

int setrlimit(int resource, const struct rlimit *rlp)
{
	return 0;
}

int tcgetattr(int fildes, struct termios *termios_p)
{
	return 0;
}

int tcsetattr(int fildes, int optional_actions,
	const struct termios *termios_p)
{
	return 0;
}

// Not really getline, just used for password input in libzfs_crypto.c
#define MAX_GETLINE 128
int32_t getline(char **linep, uint32_t* linecapp,
	FILE *stream)
{
	static char getpassbuf[MAX_GETLINE + 1];
	size_t i = 0;

	// This does not work in bash, it echos the password, find
	// a solution for it too
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode = 0;
	GetConsoleMode(hStdin, &mode);
	SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));

	int c;
	for (;;)
	{
		c = getc(stream);
		if ((c == '\r') || (c == '\n'))
		{
			getpassbuf[i] = '\0';
			break;
		}
		else if (i < MAX_GETLINE)
		{
			getpassbuf[i++] = c;
		}
		if (i >= MAX_GETLINE)
		{
			getpassbuf[i] = '\0';
			break;
		}
	}

	if (linep) *linep = strdup(getpassbuf);
	if (linecapp) *linecapp = 1;

	SetConsoleMode(hStdin, mode);

	return i;
}