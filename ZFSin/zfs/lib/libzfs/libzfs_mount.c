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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, 2015 by Delphix. All rights reserved.
 */

/*
 * Routines to manage ZFS mounts.  We separate all the nasty routines that have
 * to deal with the OS.  The following functions are the main entry points --
 * they are used by mount and unmount and when changing a filesystem's
 * mountpoint.
 *
 * 	zfs_is_mounted()
 * 	zfs_mount()
 * 	zfs_unmount()
 * 	zfs_unmountall()
 *
 * This file also contains the functions used to manage sharing filesystems via
 * NFS and iSCSI:
 *
 * 	zfs_is_shared()
 * 	zfs_share()
 * 	zfs_unshare()
 *
 * 	zfs_is_shared_nfs()
 * 	zfs_is_shared_smb()
 * 	zfs_share_proto()
 * 	zfs_shareall();
 * 	zfs_unshare_nfs()
 * 	zfs_unshare_smb()
 * 	zfs_unshareall_nfs()
 *	zfs_unshareall_smb()
 *	zfs_unshareall()
 *	zfs_unshareall_bypath()
 *
 * The following functions are available for pool consumers, and will
 * mount/unmount and share/unshare all datasets within pool:
 *
 * 	zpool_enable_datasets()
 * 	zpool_disable_datasets()
 */

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <zone.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/dsl_crypt.h>

#include <libzfs.h>
#include <fcntl.h>
#include <sys/xattr.h>

#include "libzfs_impl.h"

#include <libshare.h>
#include <sys/systeminfo.h>
#define	MAXISALEN	257	/* based on sysinfo(2) man page */

#ifdef __APPLE__
#include <sys/zfs_mount.h>
#include <CommonCrypto/CommonDigest.h>
static off_t snowflake_icon_size = 196764; // bytes
static unsigned char snowflake_icon_md[] = {0x77, 0x1b, 0x99, 0x36, 0x77, 0x8c, 0xc9, 0xb1, 0x19, 0x4e, 0x70, 0x9b, 0x9e, 0xc0, 0xf6, 0x5e}; // md5sum
#include <AvailabilityMacros.h>
#endif /* __APPLE__ */


//#dprintf printf

static int zfs_share_proto(zfs_handle_t *, zfs_share_proto_t *);
zfs_share_type_t zfs_is_shared_proto(zfs_handle_t *, char **,
    zfs_share_proto_t);
int zunmount(zfs_handle_t* zhp, const char* dir, int mflag);

/*
 * The share protocols table must be in the same order as the zfs_share_prot_t
 * enum in libzfs_impl.h
 */
typedef struct {
	zfs_prop_t p_prop;
	char *p_name;
	int p_share_err;
	int p_unshare_err;
} proto_table_t;

proto_table_t proto_table[PROTO_END] = {
	{ZFS_PROP_SHARENFS, "nfs", EZFS_SHARENFSFAILED, EZFS_UNSHARENFSFAILED},
	{ZFS_PROP_SHARESMB, "smb", EZFS_SHARESMBFAILED, EZFS_UNSHARESMBFAILED},
};

zfs_share_proto_t nfs_only[] = {
	PROTO_NFS,
	PROTO_END
};

zfs_share_proto_t smb_only[] = {
	PROTO_SMB,
	PROTO_END
};

#ifdef __APPLE__
zfs_share_proto_t afp_only[] = {
	PROTO_AFP,
	PROTO_END
};
#endif

zfs_share_proto_t share_all_proto[] = {
	PROTO_NFS,
	PROTO_SMB,
#ifdef __APPLE__
	PROTO_AFP,
#endif
	PROTO_END
};


/*
 * Search the sharetab for the given mountpoint and protocol, returning
 * a zfs_share_type_t value.
 */
#ifdef __APPLE__
extern boolean_t smb_is_mountpoint_active(const char *mountpoint);
extern boolean_t afp_is_mountpoint_active(const char *mountpoint);
#endif

static zfs_share_type_t
is_shared(libzfs_handle_t *hdl, const char *mountpoint, zfs_share_proto_t proto)
{
	char buf[MAXPATHLEN], *tab;
	char *ptr, *path;

#ifdef __APPLE__
	// Check smb, since exports may not exist
	if (proto == PROTO_SMB) {
		if (smb_is_mountpoint_active(mountpoint))
			return (SHARED_SMB);
	}
	// Check afp, since exports may not exist
	if (proto == PROTO_AFP) {
		if (afp_is_mountpoint_active(mountpoint))
			return (SHARED_AFP);
	}
#endif

	if (hdl->libzfs_sharetab == NULL)
		return (SHARED_NOT_SHARED);

	(void) fseek(hdl->libzfs_sharetab, 0, SEEK_SET);

	while (fgets(buf, sizeof (buf), hdl->libzfs_sharetab) != NULL) {

		/* the mountpoint is the first entry on each line */
		if ((tab = strchr(buf, '\t')) == NULL)
			continue;

		path = buf;

#ifdef __APPLE__
		/* In OSX we wrap the name in quotes, "name" so that spaces work */
		if (buf[0] == '"')
			path = &buf[1];
		--tab;
		if (*tab == '"') *tab = 0;
		++tab;
#endif

		*tab = '\0';
		if (strcmp(path, mountpoint) == 0) {

#ifdef __APPLE__
			/* OSX export is only NFS */
			if (proto == PROTO_NFS) {
				return (SHARED_NFS);
			}
#endif

			/*
			 * the protocol field is the third field
			 * skip over second field
			 */
			ptr = ++tab;
			if ((tab = strchr(ptr, '\t')) == NULL)
				continue;
			ptr = ++tab;
			if ((tab = strchr(ptr, '\t')) == NULL)
				continue;
			*tab = '\0';
			if (strcmp(ptr,
			    proto_table[proto].p_name) == 0) {
				switch (proto) {
				case PROTO_NFS:
					return (SHARED_NFS);
				case PROTO_SMB:
					return (SHARED_SMB);
#ifdef __APPLE__
				case PROTO_AFP:
					return (SHARED_AFP);
#endif
				default:
					return (0);
				}
			}
		}
	}

	return (SHARED_NOT_SHARED);
}

static boolean_t
dir_is_empty_stat(const char *dirname)
{
	struct _stat64 st;

	/*
	 * We only want to return false if the given path is a non empty
	 * directory, all other errors are handled elsewhere.
	 */
	if (stat(dirname, (struct stat*)&st) < 0 || !S_ISDIR(st.st_mode)) {
		return (B_TRUE);
	}

	/*
	 * An empty directory will still have two entries in it, one
	 * entry for each of "." and "..".
	 */
	if (st.st_size > 2) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * "openat" came to OS X Version 10.10.
 */
#if defined (MAC_OS_X_VERSION_10_10) && \
            (MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10)
static boolean_t
dir_is_empty_readdir(const char *dirname)
{
	DIR *dirp;
	struct dirent *dp;
	int dirfd;

	if ((dirfd = openat(AT_FDCWD, dirname,
	    O_RDONLY | O_NDELAY | O_CLOEXEC, 0)) < 0) {
		return (B_TRUE);
	}

	if ((dirp = fdopendir(dirfd)) == NULL) {
		(void) close(dirfd);
		return (B_TRUE);
	}

	while ((dp = readdir(dirp)) != NULL) {

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		(void) closedir(dirp);
		return (B_FALSE);
	}

	(void) closedir(dirp);
	return (B_TRUE);
}

#else /* <= MAC_OS_X_VERSION_10_9 */

static boolean_t
dir_is_empty_readdir(const char *dirname)
{
	DIR *dirp;
	struct dirent *dp;

	if ((dirp = opendir(dirname)) == NULL)
		return (B_TRUE);

	while ((dp = readdir(dirp)) != NULL) {

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		(void) closedir(dirp);
		return (B_FALSE);
	}

	(void) closedir(dirp);
	return (B_TRUE);
}


#endif

 /*
 * Returns true if the specified directory is empty.  If we can't open the
 * directory at all, return true so that the mount can fail with a more
 * informative error message.
 */
static boolean_t
dir_is_empty(const char *dirname)
{
	struct statfs st;

	/*
	 * If the statvfs call fails or the filesystem is not a ZFS
	 * filesystem, fall back to the slow path which uses readdir.
	 */
	if ((statfs(dirname, &st) != 0) ||
	    (strcmp(st.f_fstypename, "zfs") != 0)) {
		return (dir_is_empty_readdir(dirname));
	}

	/*
	 * At this point, we know the provided path is on a ZFS
	 * filesystem, so we can use stat instead of readdir to
	 * determine if the directory is empty or not. We try to avoid
	 * using readdir because that requires opening "dirname"; this
	 * open file descriptor can potentially end up in a child
	 * process if there's a concurrent fork, thus preventing the
	 * zfs_mount() from otherwise succeeding (the open file
	 * descriptor inherited by the child process will cause the
	 * parent's mount to fail with EBUSY). The performance
	 * implications of replacing the open, read, and close with a
	 * single stat is nice; but is not the main motivation for the
	 * added complexity.
	 */
	return (dir_is_empty_stat(dirname));
}



/*
 * Checks to see if the mount is active.  If the filesystem is mounted, we fill
 * in 'where' with the current mountpoint, and return 1.  Otherwise, we return
 * 0.
 */
boolean_t
is_mounted(libzfs_handle_t *zfs_hdl, const char *special, char **where)
{
	struct mnttab entry;

	if (libzfs_mnttab_find(zfs_hdl, special, &entry) != 0)
		return (B_FALSE);

	if (where != NULL)
		*where = zfs_strdup(zfs_hdl, entry.mnt_mountp);

	return (B_TRUE);
}

boolean_t
zfs_is_mounted(zfs_handle_t *zhp, char **where)
{
	return (is_mounted(zhp->zfs_hdl, zfs_get_name(zhp), where));
}

/*
 * Returns true if the given dataset is mountable, false otherwise.  Returns the
 * mountpoint in 'buf'.
 */
static boolean_t
zfs_is_mountable(zfs_handle_t *zhp, char *buf, size_t buflen,
    zprop_source_t *source)
{
	char sourceloc[MAXNAMELEN];
	char driveletter[100] = "off";
	zprop_source_t sourcetype;

	if (!zfs_prop_valid_for_type(ZFS_PROP_MOUNTPOINT, zhp->zfs_type,
	    B_FALSE))
		return (B_FALSE);

	verify(zfs_prop_get(zhp, ZFS_PROP_MOUNTPOINT, buf, buflen,
	    &sourcetype, sourceloc, sizeof (sourceloc), B_FALSE) == 0);

	if (strcmp(buf, ZFS_MOUNTPOINT_NONE) == 0 ||
	    strcmp(buf, ZFS_MOUNTPOINT_LEGACY) == 0)
		return (B_FALSE);
#ifdef _WIN32
	verify(zfs_prop_get(zhp, ZFS_PROP_DRIVELETTER, driveletter,
		sizeof(driveletter), NULL, NULL, 0, B_FALSE) == 0);

	if (strcmp(buf, "/") == 0 && 
		(strcmp(driveletter, "off") == 0 || strcmp(driveletter, "-") == 0))
		return (B_FALSE);

	if (strcmp(driveletter, "off") == 0 || 
		strcmp(driveletter, "-") == 0) {
		// if we don't mount as driveletter, check the directory
		// if file exists, it should be a directory and not a reparse point
		DWORD fileAttr = GetFileAttributes(buf);
		if (fileAttr != INVALID_FILE_ATTRIBUTES && // file exist
			(fileAttr & FILE_ATTRIBUTE_REPARSE_POINT ||
			!(fileAttr & FILE_ATTRIBUTE_DIRECTORY))) 
			return (B_FALSE);

		// if we aren't root, check parent folder, it should exist
		// This code needs to use driveletter logic, "/tank/lower" would
		// check "/tank" - which may be mounted on "F:"
#if 0
		if (strcmp(buf, "/") != 0) {
			char parent_path[MAX_PATH];
			//sprintf(parent_path, "%s/..", buf);
			strlcpy(parent_path, buf, MAX_PATH);
			//PathCchRemoveFileSpec(parent_path, MAX_PATH);
			char *tok, *last = NULL;
			tok = parent_path;
			while (tok = strpbrk(tok, "\\/")) {
				last = tok++;
			}
			if (last) *last = 0;
			fileAttr = GetFileAttributes(parent_path);
			if (fileAttr == INVALID_FILE_ATTRIBUTES || // file doesn't exist
				fileAttr & FILE_ATTRIBUTE_REPARSE_POINT ||
				!(fileAttr & FILE_ATTRIBUTE_DIRECTORY))
				return (B_FALSE); // we die here.
		}
#endif
	}
#endif

	if (zfs_prop_get_int(zhp, ZFS_PROP_CANMOUNT) == ZFS_CANMOUNT_OFF)
		return (B_FALSE);

	if (zfs_prop_get_int(zhp, ZFS_PROP_ZONED) &&
	    getzoneid() == GLOBAL_ZONEID)
		return (B_FALSE);

	if (source)
		*source = sourcetype;

	return (B_TRUE);
}

/*
 * The filesystem is mounted by invoking the system mount utility rather
 * than by the system call mount(2).  This ensures that the /etc/mtab
 * file is correctly locked for the update.  Performing our own locking
 * and /etc/mtab update requires making an unsafe assumption about how
 * the mount utility performs its locking.  Unfortunately, this also means
 * in the case of a mount failure we do not have the exact errno.  We must
 * make due with return value from the mount process.
 *
 * In the long term a shared library called libmount is under development
 * which provides a common API to address the locking and errno issues.
 * Once the standard mount utility has been updated to use this library
 * we can add an autoconf check to conditionally use it.
 *
 * http://www.kernel.org/pub/linux/utils/util-linux/libmount-docs/index.html
 */

#ifdef __LINUX__
static int
do_mount(const char *src, const char *mntpt, char *opts)
{
	char *argv[8] = {
	    "/sbin/mount",
	    "-t", MNTTYPE_ZFS,
	    "-o", opts,
	    (char *)src,
	    (char *)mntpt,
	    (char *)NULL };
	int rc;

	/* Return only the most critical mount error */
	rc = libzfs_run_process(argv[0], argv, STDOUT_VERBOSE|STDERR_VERBOSE);
	if (rc) {
		if (rc & MOUNT_FILEIO)
			return (EIO);
		if (rc & MOUNT_USER)
			return (EINTR);
		if (rc & MOUNT_SOFTWARE)
			return (EPIPE);
		if (rc & MOUNT_BUSY)
			return (EBUSY);
		if (rc & MOUNT_SYSERR)
			return (EAGAIN);
		if (rc & MOUNT_USAGE)
			return (EINVAL);

		return (ENXIO); /* Generic error */
	}

	return (0);
}
#endif /* __LINUX__ */

static int
do_unmount(zfs_handle_t *zhp, const char *mntpt, int flags)
{
	int rc;
	rc = zunmount(zhp, mntpt, flags);
	return (rc ? EINVAL : 0);
}

static int
do_unmount_volume(const char *mntpt, int flags)
{
	char force_opt[] = "force";
#ifdef __LINUX__
	char lazy_opt[] = "-l";
#endif /* __LINUX__ */
	char *argv[7] = {
	    "/usr/sbin/diskutil",
	    "unmountDisk",
	    NULL, NULL, NULL, NULL };
	int rc, count = 2;

	if (flags & MS_FORCE) {
		argv[count] = force_opt;
		count++;
	}

#ifdef __LINUX__
	if (flags & MS_DETACH) {
		argv[count] = lazy_opt;
		count++;
	}
#endif /* __LINUX__ */

	argv[count] = (char *)mntpt;
	rc = libzfs_run_process(argv[0], argv, STDOUT_VERBOSE|STDERR_VERBOSE);

	return (rc ? EINVAL : 0);
}

#ifdef __LINUX__
static int
zfs_add_option(zfs_handle_t *zhp, char *options, int len,
    zfs_prop_t prop, char *on, char *off)
{
	char *source;
	uint64_t value;

	/* Skip adding duplicate default options */
	if ((strstr(options, on) != NULL) || (strstr(options, off) != NULL))
		return (0);

	/*
	 * zfs_prop_get_int() to not used to ensure our mount options
	 * are not influenced by the current /etc/mtab contents.
	 */
	value = getprop_uint64(zhp, prop, &source);

	(void) strlcat(options, ",", len);
	(void) strlcat(options, value ? on : off, len);

	return (0);
}

static int
zfs_add_options(zfs_handle_t *zhp, char *options, int len)
{
	int error = 0;

	error = zfs_add_option(zhp, options, len,
	    ZFS_PROP_ATIME, MNTOPT_ATIME, MNTOPT_NOATIME);
	error = error ? error : zfs_add_option(zhp, options, len,
	    ZFS_PROP_DEVICES, MNTOPT_DEVICES, MNTOPT_NODEVICES);
	error = error ? error : zfs_add_option(zhp, options, len,
	    ZFS_PROP_EXEC, MNTOPT_EXEC, MNTOPT_NOEXEC);
	error = error ? error : zfs_add_option(zhp, options, len,
	    ZFS_PROP_READONLY, MNTOPT_RO, MNTOPT_RW);
	error = error ? error : zfs_add_option(zhp, options, len,
	    ZFS_PROP_SETUID, MNTOPT_SETUID, MNTOPT_NOSETUID);
	error = error ? error : zfs_add_option(zhp, options, len,
	    ZFS_PROP_XATTR, MNTOPT_XATTR, MNTOPT_NOXATTR);
	error = error ? error : zfs_add_option(zhp, options, len,
	    ZFS_PROP_NBMAND, MNTOPT_NBMAND, MNTOPT_NONBMAND);

	return (error);
}
#endif /* __LINUX */

#ifdef __APPLE__
static boolean_t
should_update_icon(FILE *current_icon)
{
	struct _stat64 sbuf;
	off_t current_icon_size;
	CC_MD5_CTX ctx;
	size_t n;
	unsigned char buf[1024];
	unsigned char current_icon_md[CC_MD5_DIGEST_LENGTH];
	int i;

	fstat(fileno(current_icon), &sbuf);
	current_icon_size = sbuf.st_size;

	if (current_icon_size != snowflake_icon_size) {
		return (B_FALSE);
	}

	CC_MD5_Init(&ctx);
	while ((n = fread(buf, 1, 1024, current_icon)) > 0) {
		CC_MD5_Update(&ctx, buf, (CC_LONG)n);
	}
	CC_MD5_Final(current_icon_md, &ctx);
	rewind(current_icon);

	for(i = 0; i < CC_MD5_DIGEST_LENGTH; i++) {
		if (current_icon_md[i] != snowflake_icon_md[i]) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * On OSX we can set the icon to an Open ZFS specific one, just to be extra
 * shiny
 */
static void
zfs_mount_seticon(const char *mountpoint)
{
	/* For a root file system, add a volume icon. */
	ssize_t attrsize;
	uint16_t finderinfo[16];
	struct _stat64 sbuf;
	char *path;
	FILE *dstfp, *srcfp;
	unsigned char buf[1024];
	unsigned int red;
	boolean_t hasicon = B_FALSE;
	boolean_t doupdatefinder = B_FALSE;
	char template[MAXPATHLEN];
	int fd = -1;

	if (asprintf(&path, "%s/%s", mountpoint, MOUNT_POINT_CUSTOM_ICON) == -1)
		return;

	if ((stat(path, &sbuf) == 0 && sbuf.st_size > 0))
		hasicon = B_TRUE;

	/* check if we can read in the default ZFS icon */
	srcfp = fopen(CUSTOM_ICON_PATH, "r");

	/* No source icon */
	if (!srcfp) {
		free(path);
		if (hasicon)
			goto setfinderinfo;
		else
			return;
	}

	if (hasicon) {
		/* Open the output icon for reading */
		dstfp = fopen(path, "r");
		if (!dstfp) {
			fclose(srcfp);
			free(path);
			goto setfinderinfo;
		}
		if (should_update_icon(dstfp) == B_FALSE) {
			fclose(srcfp);
			fclose(dstfp);
			free(path);
			goto setfinderinfo;
		} else {
			fprintf(stderr, "Updating custom icon of %s\n", mountpoint);
			doupdatefinder = B_TRUE;
			fclose(dstfp);
		}
	}

	/* Open the output icon for writing */
	dstfp = fopen(path, "w");
	if (!dstfp) {
		fclose(srcfp);
		free(path);
		goto setfinderinfo;
	}

	/* Copy icon */
	while ((red = fread(buf, 1, sizeof(buf), srcfp)) > 0)
		(void) fwrite(buf, 1, red, dstfp);

	fclose(dstfp);
	fclose(srcfp);
	free(path);
setfinderinfo:
	/* Tag the root directory as having a custom icon. */
	attrsize = getxattr(mountpoint, XATTR_FINDERINFO_NAME, &finderinfo,
	    sizeof (finderinfo), 0, 0);
	if (attrsize != sizeof (finderinfo))
		(void) memset(&finderinfo, 0, sizeof(finderinfo));

	if ((finderinfo[4] & BE_16(0x0400)) == 0) {
		finderinfo[4] |= BE_16(0x0400);
		(void) setxattr(mountpoint, XATTR_FINDERINFO_NAME, &finderinfo,
		    sizeof (finderinfo), 0, 0);
		doupdatefinder = B_TRUE;
	}

	/* Need to touch a visible file to get Finder to update */
	if (doupdatefinder) {
		strlcpy(template, mountpoint, sizeof (template));
		strlcat(template, "/tempXXXXXX", sizeof (template));
		if ((fd = mkstemp(template)) != -1) {
			unlink(template); // Just delete it right away
			close(fd);
		} else
			fprintf(stderr, "Failed to create temp file.\n");
	}
}
#endif

#ifdef __APPLE__

void osx_start_spotlight(char *mountpoint)
{
	char *argv[7] = {
	    "/usr/bin/mdutil",
		"-E",
	    NULL,
		NULL, NULL, NULL };

	// mdutil -E /mount
	argv[2] = (char *)mountpoint;
	libzfs_run_process(argv[0], argv, 0);

	// mdutil -i on /mount
	argv[1] = "-i";
	argv[2] = "on";
	argv[3] = (char *)mountpoint;
	libzfs_run_process(argv[0], argv, 0);

	printf("Enabled Spotlight on '%s'\n", mountpoint);

}

#endif

/*
 * Mount the given filesystem.
 *
 * 'flags' appears pretty much always 0 here.
 */
int
zfs_mount(zfs_handle_t *zhp, const char *options, int flags)
{
	struct _stat64 buf;
	char mountpoint[ZFS_MAXPROPLEN];
	char mntopts[MNT_LINE_MAX];
	char overlay[ZFS_MAXPROPLEN];
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	uint64_t keystatus;
	int remount = 0, rc;

	if (options == NULL) {
		mntopts[0] = '\0';
	} else {
		(void) strlcpy(mntopts, options, sizeof (mntopts));
	}

	if (strstr(mntopts, MNTOPT_REMOUNT) != NULL)
		remount = 1;

	/*
	 * If the pool is imported read-only then all mounts must be read-only
	 */
#ifdef __LINUX__
	if (zpool_get_prop_int(zhp->zpool_hdl, ZPOOL_PROP_READONLY, NULL))
		(void) strlcat(mntopts, "," MNTOPT_RO, sizeof (mntopts));
#else
	if (zpool_get_prop_int(zhp->zpool_hdl, ZPOOL_PROP_READONLY, NULL))
		flags |= MS_RDONLY;
#endif /* __LINUX__ */

	if (!zfs_is_mountable(zhp, mountpoint, sizeof (mountpoint), NULL))
		return (0);

#ifdef __LINUX__

	/*
	 * Append default mount options which apply to the mount point.
	 * This is done because under Linux (unlike Solaris) multiple mount
	 * points may reference a single super block.  This means that just
	 * given a super block there is no back reference to update the per
	 * mount point options.
	 */
	rc = zfs_add_options(zhp, &flags);
	if (rc) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "default options unavailable"));
		return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
		    dgettext(TEXT_DOMAIN, "cannot mount '%s'"),
		    mountpoint));
	}

	/*
	 * Append zfsutil option so the mount helper allow the mount
	 */
	strlcat(mntopts, "," MNTOPT_ZFSUTIL, sizeof (mntopts));
#endif /* __LINUX__ */

	/* Create the directory if it doesn't already exist */
#ifdef _WIN32
	/*
	 * If the filesystem is encrypted the key must be loaded  in order to
	 * mount. If the key isn't loaded, the MS_CRYPT flag decides whether
	 * or not we attempt to load the keys. Note: we must call
	 * zfs_refresh_properties() here since some callers of this function
	 * (most notably zpool_enable_datasets()) may implicitly load our key
	 * by loading the parent's key first.
	 */
	if (zfs_prop_get_int(zhp, ZFS_PROP_ENCRYPTION) != ZIO_CRYPT_OFF) {
		zfs_refresh_properties(zhp);
		keystatus = zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS);

		/*
		 * If the key is unavailable and MS_CRYPT is set give the
		 * user a chance to enter the key. Otherwise just fail
		 * immediately.
		 */
		if (keystatus == ZFS_KEYSTATUS_UNAVAILABLE) {
			if (flags & MS_CRYPT) {
				rc = zfs_crypto_load_key(zhp, B_FALSE, NULL);
				if (rc)
					return (rc);
			} else {
				zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
				    "encryption key not loaded"));
				return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
				    dgettext(TEXT_DOMAIN, "cannot mount '%s'"),
				    mountpoint));
			}
		}

	}

	if (zfs_get_type(zhp) != ZFS_TYPE_SNAPSHOT &&
	    lstat(mountpoint, &buf) != 0) {
#else
	if (lstat(mountpoint, &buf) != 0) {
#endif

/*
 * In windows, we do not create the directory, as it is made
 * when we create the reparse point.
 */
#ifndef _WIN32
		if (mkdirp(mountpoint, 0755) != 0) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "failed to create mountpoint"));
			return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
			    dgettext(TEXT_DOMAIN, "cannot mount '%s'"),
			    mountpoint));
		}
#endif
	}

	/*
	 * Overlay mounts are disabled by default but may be enabled
	 * via the 'overlay' property or the 'zfs mount -O' option.
	 */
	if (!(flags & MS_OVERLAY)) {
		if (zfs_prop_get(zhp, ZFS_PROP_OVERLAY, overlay,
			    sizeof (overlay), NULL, NULL, 0, B_FALSE) == 0) {
			if (strcmp(overlay, "on") == 0) {
				flags |= MS_OVERLAY;
			}
		}
	}

#ifndef _WIN32
	/*
	 * Determine if the mountpoint is empty.  If so, refuse to perform the
	 * mount.  We don't perform this check if 'remount' is
	 * specified or if overlay option(-O) is given
	 */
	if ((flags & MS_OVERLAY) == 0 && !remount &&
	    !dir_is_empty(mountpoint)) {
		zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
		    "directory is not empty"));
		return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
		    dgettext(TEXT_DOMAIN, "cannot mount '%s'"), mountpoint));
	}
#endif
	/* perform the mount */
#ifdef __LINUX__
	rc = do_mount(zfs_get_name(zhp), mountpoint, mntopts);
#elif defined(__APPLE__) || defined (__FREEBSD__) || defined (_WIN32)
	if (zmount(zhp, mountpoint, MS_OPTIONSTR | flags,
	    MNTTYPE_ZFS, NULL, 0, mntopts, sizeof (mntopts)) != 0) {
#elif defined(__illumos__)
	if (mount(zfs_get_name(zhp), mountpoint, MS_OPTIONSTR | flags,
	    MNTTYPE_ZFS, NULL, 0, mntopts, sizeof (mntopts)) != 0) {
#endif /* __LINUX__*/
		/*
		 * Generic errors are nasty, but there are just way too many
		 * from mount(), and they're well-understood.  We pick a few
		 * common ones to improve upon.
		 */
		if (errno == EBUSY) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "mountpoint or dataset is busy"));
		} else if (errno == EPERM) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "Insufficient privileges"));
		} else if (errno == ENOTSUP) {
			char buf[256];
			int spa_version;

			VERIFY(zfs_spa_version(zhp, &spa_version) == 0);
			(void) snprintf(buf, sizeof (buf),
			    dgettext(TEXT_DOMAIN, "Can't mount a version %lld "
			    "file system on a version %d pool. Pool must be"
			    " upgraded to mount this file system."),
			    (u_longlong_t)zfs_prop_get_int(zhp,
			    ZFS_PROP_VERSION), spa_version);
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN, buf));
#ifdef _WIN32
		} else if (((errno == ESRCH) || (errno == EINVAL) ||
		    (errno == ENOENT && lstat(mountpoint, &buf) != 0)) &&
		    zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT) {
			zfs_error_aux(hdl, dgettext(TEXT_DOMAIN,
			    "The parent file system must be mounted first."));
#endif
		} else {
			zfs_error_aux(hdl, strerror(errno));
		}
		return (zfs_error_fmt(hdl, EZFS_MOUNTFAILED,
		    dgettext(TEXT_DOMAIN, "cannot mount '%s'"),
		    zhp->zfs_name));
	}

#ifdef __APPLE__
	if (zhp->zfs_type == ZFS_TYPE_SNAPSHOT)
		fprintf(stderr, "ZFS: snapshot mountpoint '%s'\n", mountpoint);

	if (!(flags & MS_RDONLY)) {

		zfs_mount_seticon(mountpoint);

		/*
		 * We automatically created root ".metadate_index_never" files while
		 * spotlight support was broken, we will be nice and try to clean
		 * those up here, if the file date is older than before the release
		 * with spotlight support. (So if users create newer, they want
		 * spotlist disabled)
		 * This should probably be removed after next release. (1.4.0?)
		 */
		char *path;
		if (asprintf(&path, "%s/.metadata_never_index", mountpoint) > 0) {
			struct _stat64 stsb;
			/* UTC: Fri, 01 May 2015 00:00:00 +0000 */
			if (!stat(path, &stsb) && (stsb.st_mtime < 1430438400)) {
				unlink(path);
				osx_start_spotlight(mountpoint);
			}
			free(path);
		}

		/* If we mount without DA, it fails to create .Trashes folder, so
		 * we manually attempt to create it here until proper integration
		 * is complete
		 */
		{
			char *path;
			struct _stat64 stsb;
			if (asprintf(&path,
				"%s/.Trashes", mountpoint) > 0) {

				if (lstat(path, &stsb) != 0) { /* Not there */
					if (!mkdir(path, (mode_t)0333))
						(void)chmod(path, (mode_t)01333);
				}
				free(path);
			}
		}
	}
#endif

	/* remove the mounted entry before re-adding on remount */
	if (remount)
		libzfs_mnttab_remove(hdl, zhp->zfs_name);

	/* add the mounted entry into our cache */
	libzfs_mnttab_add(hdl, zfs_get_name(zhp), mountpoint, mntopts);
	return (0);
}

/*
 * Unmount a single filesystem.
 */
static int
unmount_one(zfs_handle_t *zhp, const char *mountpoint, int flags)
{
    int error;
    error = do_unmount(zhp, mountpoint, flags);
    if (error != 0) {
        return (zfs_error_fmt(zhp->zfs_hdl, EZFS_UMOUNTFAILED,
                              dgettext(TEXT_DOMAIN, "cannot unmount '%s'"),
                    mountpoint));
    }

	return (0);
}

/*
 * Unmount the given filesystem.
 */
int
zfs_unmount(zfs_handle_t *zhp, const char *mountpoint, int flags)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
#ifdef __LINUX__
	struct mnttab search = { 0 }, entry;
#else
	struct mnttab entry;
#endif /* __LINUX__ */
	char *mntpt = NULL;

	/* check to see if need to unmount the filesystem */
	if (mountpoint != NULL ||
	    (((zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) ||
	    (zfs_get_type(zhp) == ZFS_TYPE_SNAPSHOT)) &&
	    libzfs_mnttab_find(hdl, zhp->zfs_name, &entry) == 0)) {

		/*
		 * mountpoint may have come from a call to
		 * getmnt/getmntany if it isn't NULL. If it is NULL,
		 * we know it comes from getmntany which can then get
		 * overwritten later. We strdup it to play it safe.
		 */
		if (mountpoint == NULL)
			mntpt = zfs_strdup(zhp->zfs_hdl, entry.mnt_mountp);
		else
			mntpt = zfs_strdup(zhp->zfs_hdl, mountpoint);

		/*
		 * Unshare and unmount the filesystem
		 */
#ifdef __illumos__
		if (zfs_unshare_proto(zhp, mntpt, share_all_proto) != 0)
#else
		if (zfs_unshare_nfs(zhp, mntpt) != 0)
#endif
		return (-1);

		if (unmount_one(zhp, mntpt, flags) != 0) {
			free(mntpt);
#ifdef __illumos__
			(void) zfs_shareall(zhp);
#else
			(void) zfs_share_nfs(zhp);
#endif
			return (-1);
		}
		libzfs_mnttab_remove(hdl, zhp->zfs_name);
		free(mntpt);

	}

	return (0);
}

/*
 * Unmount this filesystem and any children inheriting the mountpoint property.
 * To do this, just act like we're changing the mountpoint property, but don't
 * remount the filesystems afterwards.
 */
int
zfs_unmountall(zfs_handle_t *zhp, int flags)
{
	prop_changelist_t *clp;
	int ret;

	clp = changelist_gather(zhp, ZFS_PROP_MOUNTPOINT, 0, flags);
	if (clp == NULL)
		return (-1);

	ret = changelist_prefix(clp);
	changelist_free(clp);

	return (ret);
}

boolean_t
zfs_is_shared(zfs_handle_t *zhp)
{
	zfs_share_type_t rc = 0;
	zfs_share_proto_t *curr_proto;

	if (ZFS_IS_VOLUME(zhp))
		return (B_FALSE);

	for (curr_proto = share_all_proto; *curr_proto != PROTO_END;
	    curr_proto++)
		rc |= zfs_is_shared_proto(zhp, NULL, *curr_proto);

	return (rc ? B_TRUE : B_FALSE);
}

int
zfs_share(zfs_handle_t *zhp)
{
	assert(!ZFS_IS_VOLUME(zhp));
	return (zfs_share_proto(zhp, share_all_proto));
}

int
zfs_unshare(zfs_handle_t *zhp)
{
	assert(!ZFS_IS_VOLUME(zhp));
	return (zfs_unshareall(zhp));
}

/*
 * Check to see if the filesystem is currently shared.
 */
zfs_share_type_t
zfs_is_shared_proto(zfs_handle_t *zhp, char **where, zfs_share_proto_t proto)
{
	char *mountpoint;
	zfs_share_type_t rc;

	if (!zfs_is_mounted(zhp, &mountpoint))
		return (SHARED_NOT_SHARED);

	if ((rc = is_shared(zhp->zfs_hdl, mountpoint, proto))) {
		if (where != NULL)
			*where = mountpoint;
		else
			free(mountpoint);
		return (rc);
	} else {
		free(mountpoint);
		return (SHARED_NOT_SHARED);
	}
}

boolean_t
zfs_is_shared_nfs(zfs_handle_t *zhp, char **where)
{
	return (zfs_is_shared_proto(zhp, where,
	    PROTO_NFS) != SHARED_NOT_SHARED);
}

boolean_t
zfs_is_shared_smb(zfs_handle_t *zhp, char **where)
{
	return (zfs_is_shared_proto(zhp, where,
	    PROTO_SMB) != SHARED_NOT_SHARED);
}

#ifdef __APPLE__
boolean_t
zfs_is_shared_afp(zfs_handle_t *zhp, char **where)
{
	return (zfs_is_shared_proto(zhp, where,
	    PROTO_AFP) != SHARED_NOT_SHARED);
}
#endif

/*
 * zfs_init_libshare(zhandle, service)
 *
 * Initialize the libshare API if it hasn't already been initialized.
 * In all cases it returns 0 if it succeeded and an error if not. The
 * service value is which part(s) of the API to initialize and is a
 * direct map to the libshare sa_init(service) interface.
 */
int
zfs_init_libshare(libzfs_handle_t *zhandle, int service)
{
	int ret = SA_OK;

	if (ret == SA_OK && zhandle->libzfs_shareflags & ZFSSHARE_MISS) {
		/*
		 * We had a cache miss. Most likely it is a new ZFS
		 * dataset that was just created. We want to make sure
		 * so check timestamps to see if a different process
		 * has updated any of the configuration. If there was
		 * some non-ZFS change, we need to re-initialize the
		 * internal cache.
		 */
		zhandle->libzfs_shareflags &= ~ZFSSHARE_MISS;
		if (sa_needs_refresh(zhandle->libzfs_sharehdl)) {
			zfs_uninit_libshare(zhandle);
			zhandle->libzfs_sharehdl = sa_init(service);
		}
	}

	if (ret == SA_OK && zhandle && zhandle->libzfs_sharehdl == NULL)
		zhandle->libzfs_sharehdl = sa_init(service);

	if (ret == SA_OK && zhandle->libzfs_sharehdl == NULL)
		ret = SA_NO_MEMORY;

	return (ret);
}

/*
 * zfs_uninit_libshare(zhandle)
 *
 * Uninitialize the libshare API if it hasn't already been
 * uninitialized. It is OK to call multiple times.
 */
void
zfs_uninit_libshare(libzfs_handle_t *zhandle)
{
	if (zhandle != NULL && zhandle->libzfs_sharehdl != NULL) {
		sa_fini(zhandle->libzfs_sharehdl);
		zhandle->libzfs_sharehdl = NULL;
	}
}

/*
 * zfs_parse_options(options, proto)
 *
 * Call the legacy parse interface to get the protocol specific
 * options using the NULL arg to indicate that this is a "parse" only.
 */
int
zfs_parse_options(char *options, zfs_share_proto_t proto)
{
	return (sa_parse_legacy_options(NULL, options,
	    proto_table[proto].p_name));
}

/*
 * Share the given filesystem according to the options in the specified
 * protocol specific properties (sharenfs, sharesmb, shareafp).  We rely
 * on "libshare" to do the dirty work for us.
 */
static int
zfs_share_proto(zfs_handle_t *zhp, zfs_share_proto_t *proto)
{
	char mountpoint[ZFS_MAXPROPLEN];
	char shareopts[ZFS_MAXPROPLEN];
	char sourcestr[ZFS_MAXPROPLEN];
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	sa_share_t share;
	zfs_share_proto_t *curr_proto;
	zprop_source_t sourcetype;
	int ret;

	if (!zfs_is_mountable(zhp, mountpoint, sizeof (mountpoint), NULL))
		return (0);

	if ((ret = zfs_init_libshare(hdl, SA_INIT_SHARE_API)) != SA_OK) {
		(void) zfs_error_fmt(hdl, EZFS_SHARENFSFAILED,
		    dgettext(TEXT_DOMAIN, "cannot share '%s': %s"),
		    zfs_get_name(zhp), sa_errorstr(ret));
		return (-1);
	}

	for (curr_proto = proto; *curr_proto != PROTO_END; curr_proto++) {
		/*
		 * Return success if there are no share options.
		 */
		if (zfs_prop_get(zhp, proto_table[*curr_proto].p_prop,
		    shareopts, sizeof (shareopts), &sourcetype, sourcestr,
		    ZFS_MAXPROPLEN, B_FALSE) != 0 ||
		    strcmp(shareopts, "off") == 0)
			continue;

		/*
		 * If the 'zoned' property is set, then zfs_is_mountable()
		 * will have already bailed out if we are in the global zone.
		 * But local zones cannot be NFS servers, so we ignore it for
		 * local zones as well.
		 */
		if (zfs_prop_get_int(zhp, ZFS_PROP_ZONED))
			continue;

		share = sa_find_share(hdl->libzfs_sharehdl, mountpoint);
		if (share == NULL) {
			/*
			 * This may be a new file system that was just
			 * created so isn't in the internal cache
			 * (second time through). Rather than
			 * reloading the entire configuration, we can
			 * assume ZFS has done the checking and it is
			 * safe to add this to the internal
			 * configuration.
			 */
			if (sa_zfs_process_share(hdl->libzfs_sharehdl,
			    NULL, NULL, mountpoint,
			    proto_table[*curr_proto].p_name, sourcetype,
			    shareopts, sourcestr, zhp->zfs_name) != SA_OK) {
#if 0 // bring this back when we do sharing, for now just silencing mounts
				(void) zfs_error_fmt(hdl,
				    proto_table[*curr_proto].p_share_err,
				    dgettext(TEXT_DOMAIN, "cannot share '%s'"),
				    zfs_get_name(zhp));
#endif
				return (-1);
			}
			hdl->libzfs_shareflags |= ZFSSHARE_MISS;
			share = sa_find_share(hdl->libzfs_sharehdl,
			    mountpoint);
		}
		if (share != NULL) {
			int err;
			err = sa_enable_share(share,
			    proto_table[*curr_proto].p_name);
			if (err != SA_OK) {
				(void) zfs_error_fmt(hdl,
				    proto_table[*curr_proto].p_share_err,
				    dgettext(TEXT_DOMAIN, "cannot share '%s'"),
				    zfs_get_name(zhp));
				return (-1);
			}
		} else {
			(void) zfs_error_fmt(hdl,
			    proto_table[*curr_proto].p_share_err,
			    dgettext(TEXT_DOMAIN, "cannot share '%s'"),
			    zfs_get_name(zhp));
			return (-1);
		}

	}
	return (0);
}


int
zfs_share_nfs(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, nfs_only));
}

int
zfs_share_smb(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, smb_only));
}

#ifdef __APPLE__
int
zfs_share_afp(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, afp_only));
}
#endif

int
zfs_shareall(zfs_handle_t *zhp)
{
	return (zfs_share_proto(zhp, share_all_proto));
}

/*
 * Unshare a filesystem by mountpoint.
 */
static int
unshare_one(libzfs_handle_t *hdl, const char *name, const char *mountpoint,
    zfs_share_proto_t proto)
{
	sa_share_t share;
	int err;
	char *mntpt;
	/*
	 * Mountpoint could get trashed if libshare calls getmntany
	 * which it does during API initialization, so strdup the
	 * value.
	 */
	mntpt = zfs_strdup(hdl, mountpoint);

	/* make sure libshare initialized */
	if ((err = zfs_init_libshare(hdl, SA_INIT_SHARE_API)) != SA_OK) {
		free(mntpt);	/* don't need the copy anymore */
		return (zfs_error_fmt(hdl, EZFS_SHARENFSFAILED,
		    dgettext(TEXT_DOMAIN, "cannot unshare '%s': %s"),
		    name, sa_errorstr(err)));
	}

	share = sa_find_share(hdl->libzfs_sharehdl, mntpt);
	free(mntpt);	/* don't need the copy anymore */

	if (share != NULL) {
		err = sa_disable_share(share, proto_table[proto].p_name);
		if (err != SA_OK) {
			return (zfs_error_fmt(hdl, EZFS_UNSHARENFSFAILED,
			    dgettext(TEXT_DOMAIN, "cannot unshare '%s': %s"),
			    name, sa_errorstr(err)));
		}
	} else {
		return (zfs_error_fmt(hdl, EZFS_UNSHARENFSFAILED,
		    dgettext(TEXT_DOMAIN, "cannot unshare '%s': not found"),
		    name));
	}
	return (0);
}

/*
 * Unshare the given filesystem.
 */
int
zfs_unshare_proto(zfs_handle_t *zhp, const char *mountpoint,
    zfs_share_proto_t *proto)
{
	libzfs_handle_t *hdl = zhp->zfs_hdl;
	struct mnttab entry;
	char *mntpt = NULL;

	/* check to see if need to unmount the filesystem */
	if (mountpoint != NULL)
		mountpoint = mntpt = zfs_strdup(hdl, mountpoint);

	if (mountpoint != NULL || ((zfs_get_type(zhp) == ZFS_TYPE_FILESYSTEM) &&
	    libzfs_mnttab_find(hdl, zfs_get_name(zhp), &entry) == 0)) {
		zfs_share_proto_t *curr_proto;

		if (mountpoint == NULL)
			mntpt = zfs_strdup(zhp->zfs_hdl, entry.mnt_mountp);

		for (curr_proto = proto; *curr_proto != PROTO_END;
		    curr_proto++) {

			if (is_shared(hdl, mntpt, *curr_proto) &&
			    unshare_one(hdl, zhp->zfs_name,
					mntpt, *curr_proto) != 0) {
				if (mntpt != NULL)
					free(mntpt);
				return (-1);
			}
		}
	}
	if (mntpt != NULL)
		free(mntpt);

	return (0);
}

int
zfs_unshare_nfs(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, nfs_only));
}

int
zfs_unshare_smb(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, smb_only));
}

#ifdef __APPLE__
int
zfs_unshare_afp(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, afp_only));
}
#endif

/*
 * Same as zfs_unmountall(), but for NFS and SMB unshares.
 */
int
zfs_unshareall_proto(zfs_handle_t *zhp, zfs_share_proto_t *proto)
{
	prop_changelist_t *clp;
	int ret;

	clp = changelist_gather(zhp, ZFS_PROP_SHARENFS, 0, 0);
	if (clp == NULL)
		return (-1);

	ret = changelist_unshare(clp, proto);
	changelist_free(clp);

	return (ret);
}

int
zfs_unshareall_nfs(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, nfs_only));
}

int
zfs_unshareall_smb(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, smb_only));
}

#ifdef __APPLE__
int
zfs_unshareall_afp(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, afp_only));
}
#endif

int
zfs_unshareall(zfs_handle_t *zhp)
{
	return (zfs_unshareall_proto(zhp, share_all_proto));
}

int
zfs_unshareall_bypath(zfs_handle_t *zhp, const char *mountpoint)
{
	return (zfs_unshare_proto(zhp, mountpoint, share_all_proto));
}

/*
 * Remove the mountpoint associated with the current dataset, if necessary.
 * We only remove the underlying directory if:
 *
 *	- The mountpoint is not 'none' or 'legacy'
 *	- The mountpoint is non-empty
 *	- The mountpoint is the default or inherited
 *	- The 'zoned' property is set, or we're in a local zone
 *
 * Any other directories we leave alone.
 */
void
remove_mountpoint(zfs_handle_t *zhp)
{
	char mountpoint[ZFS_MAXPROPLEN];
	zprop_source_t source;

	if (!zfs_is_mountable(zhp, mountpoint, sizeof (mountpoint),
	    &source))
		return;
	if (source == ZPROP_SRC_DEFAULT ||
	    source == ZPROP_SRC_INHERITED) {
		/*
		 * Try to remove the directory, silently ignoring any errors.
		 * The filesystem may have since been removed or moved around,
		 * and this error isn't really useful to the administrator in
		 * any way.
		 */
		(void) rmdir(mountpoint);
	}
}

void
libzfs_add_handle(get_all_cb_t *cbp, zfs_handle_t *zhp)
{
	if (cbp->cb_alloc == cbp->cb_used) {
		size_t newsz;
		void *ptr;

		newsz = cbp->cb_alloc ? cbp->cb_alloc * 2 : 64;
		ptr = zfs_realloc(zhp->zfs_hdl,
		    cbp->cb_handles, cbp->cb_alloc * sizeof (void *),
		    newsz * sizeof (void *));
		cbp->cb_handles = ptr;
		cbp->cb_alloc = newsz;
	}
	cbp->cb_handles[cbp->cb_used++] = zhp;
}

static int
mount_cb(zfs_handle_t *zhp, void *data)
{
	get_all_cb_t *cbp = data;

	if (!(zfs_get_type(zhp) & ZFS_TYPE_FILESYSTEM)) {
		zfs_close(zhp);
		return (0);
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_CANMOUNT) == ZFS_CANMOUNT_NOAUTO) {
		zfs_close(zhp);
		return (0);
	}

	if (zfs_prop_get_int(zhp, ZFS_PROP_KEYSTATUS) ==
	    ZFS_KEYSTATUS_UNAVAILABLE) {
		zfs_close(zhp);
		return (0);
	}

	/*
	 * If this filesystem is inconsistent and has a receive resume
	 * token, we can not mount it.
	 */
	if (zfs_prop_get_int(zhp, ZFS_PROP_INCONSISTENT) &&
	    zfs_prop_get(zhp, ZFS_PROP_RECEIVE_RESUME_TOKEN,
	    NULL, 0, NULL, NULL, 0, B_TRUE) == 0) {
		zfs_close(zhp);
		return (0);
	}

	libzfs_add_handle(cbp, zhp);
	if (zfs_iter_filesystems(zhp, mount_cb, cbp) != 0) {
		zfs_close(zhp);
		return (-1);
	}
	return (0);
}

int
libzfs_dataset_cmp(const void *a, const void *b)
{
	zfs_handle_t **za = (zfs_handle_t **)a;
	zfs_handle_t **zb = (zfs_handle_t **)b;
	char mounta[MAXPATHLEN];
	char mountb[MAXPATHLEN];
	boolean_t gota, gotb;

	if ((gota = (zfs_get_type(*za) == ZFS_TYPE_FILESYSTEM)) != 0)
		verify(zfs_prop_get(*za, ZFS_PROP_MOUNTPOINT, mounta,
		    sizeof (mounta), NULL, NULL, 0, B_FALSE) == 0);
	if ((gotb = (zfs_get_type(*zb) == ZFS_TYPE_FILESYSTEM)) != 0)
		verify(zfs_prop_get(*zb, ZFS_PROP_MOUNTPOINT, mountb,
		    sizeof (mountb), NULL, NULL, 0, B_FALSE) == 0);

	if (gota && gotb)
		return (strcmp(mounta, mountb));

	if (gota)
		return (-1);
	if (gotb)
		return (1);

	return (strcmp(zfs_get_name(a), zfs_get_name(b)));
}

/*
 * Mount and share all datasets within the given pool.  This assumes that no
 * datasets within the pool are currently mounted.  Because users can create
 * complicated nested hierarchies of mountpoints, we first gather all the
 * datasets and mountpoints within the pool, and sort them by mountpoint.  Once
 * we have the list of all filesystems, we iterate over them in order and mount
 * and/or share each one.
 */
int
zpool_enable_datasets(zpool_handle_t *zhp, const char *mntopts, int flags)
{
	get_all_cb_t cb = { 0 };
	libzfs_handle_t *hdl = zhp->zpool_hdl;
	zfs_handle_t *zfsp;
	int i, ret = -1;
	int *good;
	/*
	 * Gather all non-snap datasets within the pool.
	 */
	if ((zfsp = zfs_open(hdl, zhp->zpool_name, ZFS_TYPE_DATASET)) == NULL)
		goto out;

	libzfs_add_handle(&cb, zfsp);
	if (zfs_iter_filesystems(zfsp, mount_cb, &cb) != 0)
		goto out;
	/*
	 * Sort the datasets by mountpoint.
	 */
	qsort(cb.cb_handles, cb.cb_used, sizeof (void *),
	    libzfs_dataset_cmp);

	/*
	 * And mount all the datasets, keeping track of which ones
	 * succeeded or failed.
	 */
	if ((good = zfs_alloc(zhp->zpool_hdl,
	    cb.cb_used * sizeof (int))) == NULL)
		goto out;

	ret = 0;
	for (i = 0; i < cb.cb_used; i++) {
		/*
		 * don't attempt to mount encrypted datasets with
		 * unloaded keys
		 */
		if (zfs_prop_get_int(cb.cb_handles[i], ZFS_PROP_KEYSTATUS) ==
		    ZFS_KEYSTATUS_UNAVAILABLE)
			continue;

		if (zfs_mount(cb.cb_handles[i], mntopts, flags) != 0)
			ret = -1;
		else
			good[i] = 1;
	}

	/*
	 * Then share all the ones that need to be shared. This needs
	 * to be a separate pass in order to avoid excessive reloading
	 * of the configuration. Good should never be NULL since
	 * zfs_alloc is supposed to exit if memory isn't available.
	 */
	for (i = 0; i < cb.cb_used; i++) {
		if (good[i] && zfs_share(cb.cb_handles[i]) != 0)
			ret = -1;
	}

	free(good);

out:
	for (i = 0; i < cb.cb_used; i++)
		zfs_close(cb.cb_handles[i]);
	free(cb.cb_handles);

	return (ret);
}

static int
mountpoint_compare(const void *a, const void *b)
{
	const char *mounta = *((char **)a);
	const char *mountb = *((char **)b);

	return (strcmp(mountb, mounta));
}


int
zpool_disable_volumes(zfs_handle_t *nzhp, void *data)
{
	// Same pool?
	if (nzhp && nzhp->zpool_hdl && zpool_get_name(nzhp->zpool_hdl) &&
	    data && !strcmp(zpool_get_name(nzhp->zpool_hdl), (char *)data)) {
		if (zfs_get_type(nzhp) == ZFS_TYPE_VOLUME) {
			char *volume = NULL;
			/*
			 *	/var/run/zfs/zvol/dsk/$POOL/$volume
			 */
			volume = zfs_asprintf(nzhp->zfs_hdl,
			    "%s/zfs/zvol/dsk/%s",
			    ZVOL_ROOT,
			    zfs_get_name(nzhp));
			if (volume) {
				/* Unfortunately, diskutil does not handle our
				 * symlink to /dev/diskX - so we need to
				 * readlink() to find the path
				 */
				char dstlnk[MAXPATHLEN];
				int ret;
				ret = readlink(volume, dstlnk, sizeof(dstlnk));
				if (ret > 0) {
					printf("Attempting to eject volume "
					    "'%s'\n", zfs_get_name(nzhp));
					dstlnk[ret] = '\0';
					do_unmount_volume(dstlnk, 0);
				} else {
					printf("Unable to automatically unmount ZVOL, is 'zed' running?\n");
					printf("Use 'diskutil unmountdisk /dev/diskX' to complete export.\n");
				}
				free(volume);
			}
		}
	}
	(void) zfs_iter_children(nzhp, zpool_disable_volumes, data);
	zfs_close(nzhp);
	return (0);
}

/*
 * Unshare and unmount all datasets within the given pool.  We don't want to
 * rely on traversing the DSL to discover the filesystems within the pool,
 * because this may be expensive (if not all of them are mounted), and can fail
 * arbitrarily (on I/O error, for example).  Instead, we walk /etc/mtab and
 * gather all the filesystems that are currently mounted.
 */
int
zpool_disable_datasets(zpool_handle_t *zhp, boolean_t force)
{
	int used, alloc;
	struct mnttab entry;
	size_t namelen;
	char **mountpoints = NULL;
	zfs_handle_t **datasets = NULL;
	libzfs_handle_t *hdl = zhp->zpool_hdl;
	int i;
	int ret = -1;
	int flags = (force ? MS_FORCE : 0);

	namelen = strlen(zhp->zpool_name);

#ifdef LINUX
	/* Reopen MNTTAB to prevent reading stale data from open file */
	if (freopen(MNTTAB, "r", hdl->libzfs_mnttab) == NULL)
		return (ENOENT);
#endif

	used = alloc = 0;
	while (getmntent(hdl->libzfs_mnttab, &entry) == 0) {
		/*
		 * Ignore filesystems not within this pool.
		 */
		if (entry.mnt_fstype == NULL ||
		    strncmp(entry.mnt_special, zhp->zpool_name, namelen) != 0 ||
		    (entry.mnt_special[namelen] != '/' &&
#ifdef _WIN32
		    /*
		     * On OS X, '@' is possible too since we're temporarily
		     * allowing manual snapshot mounting.
		     */
		    entry.mnt_special[namelen] != '@' &&
#endif /* __APPLE__ */
		    entry.mnt_special[namelen] != '\0'))
			continue;

		/*
		 * At this point we've found a filesystem within our pool.  Add
		 * it to our growing list.
		 */
		if (used == alloc) {
			if (alloc == 0) {
				if ((mountpoints = zfs_alloc(hdl,
				    8 * sizeof (void *))) == NULL)
					goto out;

				if ((datasets = zfs_alloc(hdl,
				    8 * sizeof (void *))) == NULL)
					goto out;

				alloc = 8;
			} else {
				void *ptr;

				if ((ptr = zfs_realloc(hdl, mountpoints,
				    alloc * sizeof (void *),
				    alloc * 2 * sizeof (void *))) == NULL)
					goto out;
				mountpoints = ptr;

				if ((ptr = zfs_realloc(hdl, datasets,
				    alloc * sizeof (void *),
				    alloc * 2 * sizeof (void *))) == NULL)
					goto out;
				datasets = ptr;

				alloc *= 2;
			}
		}

               if ((mountpoints[used] = zfs_strdup(hdl,
                    entry.mnt_mountp)) == NULL)
                        goto out;

		/*
		 * This is allowed to fail, in case there is some I/O error.  It
		 * is only used to determine if we need to remove the underlying
		 * mountpoint, so failure is not fatal.
		 */
		datasets[used] = make_dataset_handle(hdl, entry.mnt_special);

		used++;
	}

	/*
	 * At this point, we have the entire list of filesystems, so sort it by
	 * mountpoint.
	 */
	qsort(mountpoints, used, sizeof (char *), mountpoint_compare);

	/*
	 * Walk through and first unshare everything.
	 */
	for (i = 0; i < used; i++) {
		zfs_share_proto_t *curr_proto;
		for (curr_proto = share_all_proto; *curr_proto != PROTO_END;
		    curr_proto++) {

#if __APPLE__
			/* Since shares can be exported manually, we need to let
			 * users do that so if the share property is off, we
			 * assume ZFS isn't sharing the fs
			 */
			char shareopts[ZFS_MAXPROPLEN];
			char sourcestr[ZFS_MAXPROPLEN];
			zprop_source_t sourcetype;
			if (datasets[i])
				if (zfs_prop_get(datasets[i], proto_table[*curr_proto].p_prop,
							 shareopts, sizeof (shareopts),
							 &sourcetype, sourcestr,
							 ZFS_MAXPROPLEN, B_FALSE) != 0 ||
					strcmp(shareopts, "off") == 0)
					continue;
#endif
			if (is_shared(hdl, mountpoints[i], *curr_proto) &&
			    unshare_one(hdl, mountpoints[i],
			    mountpoints[i], *curr_proto) != 0)
				goto out;
		}
	}

	/*
	 * Now unmount everything, removing the underlying directories as
	 * appropriate.
	 */
	for (i = 0; i < used; i++) {
		if (unmount_one(datasets[i], mountpoints[i], flags) != 0)
			goto out;
	}

	for (i = 0; i < used; i++) {
		if (datasets[i])
			remove_mountpoint(datasets[i]);
	}

    // Surely there exists a better way to iterate a POOL to find its ZVOLs?
    zfs_iter_root(hdl, zpool_disable_volumes, (void *) zpool_get_name(zhp));

	ret = 0;
out:
	for (i = 0; i < used; i++) {
		if (datasets[i])
			zfs_close(datasets[i]);
		free(mountpoints[i]);
	}
	free(datasets);
	free(mountpoints);

	return (ret);
}
