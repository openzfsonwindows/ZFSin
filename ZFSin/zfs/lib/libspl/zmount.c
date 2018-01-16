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

/*
 * This file implements Solaris compatible zmount() function.
 */


#include <sys/mount.h>
#include <sys/zfs_mount.h>
#include <libzfs_impl.h>
#include <sys/zfs_ioctl.h>
#include <sys/w32_types.h>

int
zmount(zfs_handle_t *zhp, const char *dir, int mflag, char *fstype,
	char *dataptr, int datalen, char *optptr, int optlen)
{
	int ret = 0;

	// mount 'spec' "tank/joe" on path 'dir' "/home/joe".
	fprintf(stderr, "zmount running, emulating Unix mount\r\n"); fflush(stderr);
	zfs_cmd_t zc = { "\0" };

	(void)strlcpy(zc.zc_name, zhp->zfs_name, sizeof(zc.zc_name));
	//(void)strlcpy(zc.zc_value, dir, sizeof(zc.zc_value));

	// Setup mount point, then convert Unix slash to Win32 backslash
	//(void)strlcpy(zc.zc_value, "\\??\\c:\\BOOM", sizeof(zc.zc_value));
	// example assumes "C:" - we need to go find drive letter here.
	snprintf(zc.zc_value, sizeof(zc.zc_value), "\\??\\c:%s", dir); // "\\??\\c:/BOOM/lower"
	for (int i = 0; zc.zc_value[i]; i++)
		if (zc.zc_value[i] == '/')
			zc.zc_value[i] = '\\'; // "\\??\\c:\\BOOM\\lower"

	ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_MOUNT, &zc);

	fprintf(stderr, "zmount(%s,%s) returns %d\n",
		zhp->zfs_name, dir, ret);

	fprintf(stderr, "'%s' mounted on %s\r\n", zc.zc_name, zc.zc_value);

	// For BOOM, we get back 
	// "\\Device\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\"
	// which is the volume name, and the FS device attached to it is:
	// "\\\??\\\Volume{7cc383a0-beac-11e7-b56d-02150b22a130}"
	// and if change that to "\\\\?\\Volume{7cc383a0-beac-11e7-b56d-02150b22a130}\\";
	// we can use GetVolumePathNamesForVolumeName() to get back "\\DosDevices\\E".

	char out[MAXPATHLEN];
	DWORD outlen;

	//if (QueryDosDevice(
	//	"G:",
	//	out, MAXPATHLEN) > 0)
	//	fprintf(stderr, "'%s' mounted on %s\r\n", zc.zc_name, zc.zc_value);
	//else
	//	fprintf(stderr, "QueryDos getlast 0x%x\n", GetLastError());

	outlen = 0;
	// these give error 0x57 (invalid parameter)
	//char *name = "\\\\?\\ZFS{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\";
	//char *name = "\\\\?\\Device\\ZFS{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\";
	//char *name = "\\\\?\\Device\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\";
	//char *name = "\\\\?\\DosDevices\\Global\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\";
	// this gives error 0x1 ERROR_INVALID_FUNCTION
	//char *name = "\\\\?\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\";

	//char *name = "\\\\?\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\";
	char *name = zc.zc_value;

	// Kernel returns "\\Device\\Volume{0b1bb601-af0b-32e8-a1d2-54c167af6277}\\"
	if (strncmp(name, "\\Device\\Volume{", 15) == 0) {
		strlcpy(&name[0], "\\\\?\\", sizeof(zc.zc_value));
		strlcpy(&name[4], &name[8], sizeof(zc.zc_value));
		strlcat(name, "\\", sizeof(zc.zc_value));
	}

	fprintf(stderr, "Looking up '%s'\r\n", name);
	ret = GetVolumePathNamesForVolumeName(name, out, MAXPATHLEN, &outlen);

	if (ret != 1)
		fprintf(stderr, "GetVolumePathNamesForVolumeName ret %d outlen %d GetLastError 0x%x\n", ret, outlen, GetLastError());
	if (outlen > 0 && ret > 0) {
		char *NameIdx;
		fprintf(stderr, "%s: ", zc.zc_name);
		for (NameIdx = out;
			NameIdx[0] != '\0';
			NameIdx += strlen(NameIdx) + 1)
		{
			fprintf(stderr, "  %s", NameIdx);
		}
		fprintf(stderr, "\r\n");
	}
#if 0
	fprintf(stderr, "Trying mountmgr\r\n");
#define MOUNTMGR_DOS_DEVICE_NAME L"\\\\.\\MountPointManager"
	typedef struct _MOUNTMGR_MOUNT_POINT {
		ULONG  SymbolicLinkNameOffset;
		USHORT SymbolicLinkNameLength;
		ULONG  UniqueIdOffset;
		USHORT UniqueIdLength;
		ULONG  DeviceNameOffset;
		USHORT DeviceNameLength;
	} MOUNTMGR_MOUNT_POINT, *PMOUNTMGR_MOUNT_POINT;
#define MOUNTMGRCONTROLTYPE ((ULONG) 'm')
#define IOCTL_MOUNTMGR_QUERY_POINTS CTL_CODE(MOUNTMGRCONTROLTYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

	HANDLE mgr = CreateFileW(MOUNTMGR_DOS_DEVICE_NAME, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, INVALID_HANDLE_VALUE);
	if (mgr == INVALID_HANDLE_VALUE) return ret;

	MOUNTMGR_MOUNT_POINT input = { 0 };
	outlen = 0;
	fprintf(stderr, "sending\r\n");
	if (DeviceIoControl(mgr, IOCTL_MOUNTMGR_QUERY_POINTS, &input, sizeof(input),
		out, MAXPATHLEN, &outlen, NULL) != 0) {
		fprintf(stderr, "mountmgr returned success %d\r\n", outlen);
	}
	fprintf(stderr, "return outlen %d: GetLastError %d\r\n", outlen, GetLastError());
	CloseHandle(mgr);
#endif

#if 0
	typedef struct _REPARSE_DATA_BUFFER {
		/**
		* Reparse point tag. Must be a Microsoft reparse point tag.
		*/
		ULONG ReparseTag;
		/**
		* Size, in bytes, of the reparse data in the DataBuffer member.
		*/
		USHORT ReparseDataLength;
		/**
		* Length, in bytes, of the unparsed portion of the file name pointed
		* to by the FileName member of the associated file object.
		*/
		USHORT Reserved;
		union {
			struct {
				/** Offset, in bytes, of the substitute name string in the PathBuffer array. */
				USHORT SubstituteNameOffset;
				/** Length, in bytes, of the substitute name string. */
				USHORT SubstituteNameLength;
				/** Offset, in bytes, of the print name string in the PathBuffer array. */
				USHORT PrintNameOffset;
				/** Length, in bytes, of the print name string. */
				USHORT PrintNameLength;
				/** Used to indicate if the given symbolic link is an absolute or relative symbolic link. */
				ULONG Flags;
				/** First character of the path string. This is followed in memory by the remainder of the string. */
				WCHAR PathBuffer[1];
			} SymbolicLinkReparseBuffer;
			struct {
				/** Offset, in bytes, of the substitute name string in the PathBuffer array. */
				USHORT SubstituteNameOffset;
				/** Length, in bytes, of the substitute name string. */
				USHORT SubstituteNameLength;
				/** Offset, in bytes, of the print name string in the PathBuffer array. */
				USHORT PrintNameOffset;
				/** Length, in bytes, of the print name string. */
				USHORT PrintNameLength;
				/** First character of the path string. */
				WCHAR PathBuffer[1];
			} MountPointReparseBuffer;
			struct {
				/** Microsoft-defined data for the reparse point. */
				UCHAR DataBuffer[1];
			} GenericReparseBuffer;
		} DUMMYUNIONNAME;
	} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#pragma warning(pop)
#define REPARSE_DATA_BUFFER_HEADER_SIZE                                        \
FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

	PREPARSE_DATA_BUFFER reparseData;
	USHORT bufferLength;
	USHORT targetLength;
	BOOL result;
	ULONG resultLength;
	WCHAR targetDeviceName[MAX_PATH];

	fprintf(stderr, "making a reparse point\r\n");
	HANDLE handle;
	handle = CreateFile(L"\\DosDevices\\C:\\BOOM", GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
		FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
		NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "failed %u 0x%x\r\n", GetLastError(), GetLastError());
	}
	else {
		fprintf(stderr, "reparse point ok\r\n");
	}

	ZeroMemory(targetDeviceName, sizeof(targetDeviceName));
	wcscat_s(targetDeviceName, MAX_PATH, L"\\??\\Volume{7cc383a0-beac-11e7-b56d-02150b22a130}");

	targetLength = (USHORT)wcslen(targetDeviceName) * sizeof(WCHAR);
	bufferLength =
		FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) +
		targetLength + sizeof(WCHAR) + sizeof(WCHAR);

	reparseData = (PREPARSE_DATA_BUFFER)malloc(bufferLength);
	if (reparseData == NULL) {
		CloseHandle(handle);
		return FALSE;
	}

	ZeroMemory(reparseData, bufferLength);

	reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	reparseData->ReparseDataLength =
		bufferLength - REPARSE_DATA_BUFFER_HEADER_SIZE;

	reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
	reparseData->MountPointReparseBuffer.SubstituteNameLength = targetLength;
	reparseData->MountPointReparseBuffer.PrintNameOffset =
		targetLength + sizeof(WCHAR);
	reparseData->MountPointReparseBuffer.PrintNameLength = 0;

	RtlCopyMemory(reparseData->MountPointReparseBuffer.PathBuffer,
		targetDeviceName, targetLength);

	result = DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, reparseData,
		bufferLength, NULL, 0, &resultLength, NULL);

	CloseHandle(handle);
	free(reparseData);

	if (result) {
		fprintf(stderr, "CreateMountPoint  -> %S success\n", 
			targetDeviceName);
	}
	else {
		WCHAR errorMsg[256];
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), errorMsg, 256,
			NULL);
		fprintf(stderr, "CreateMountPoint -> %S failed: (%d) %S", 
			targetDeviceName, GetLastError(), errorMsg);
	}





	fprintf(stderr, "trying to set the mountpoint\r\n");

	ret = SetVolumeMountPoint(
		L"C:\\BOOM\\",
		L"\\\\?\\Volume{7cc383a0-beac-11e7-b56d-02150b22a130}\\"  //  This string must be of the form "\\?\Volume{GUID}\" 
	);

	fprintf(stderr, "trying to set the mountpoint: %d %d\r\n", ret, GetLastError());

#endif


	ret = 0;
	return ret;
}



int
zunmount(zfs_handle_t *zhp, const char *dir, int mflag)
{
	int ret = 0;

	// mount 'spec' "tank/joe" on path 'dir' "/home/joe".
	fprintf(stderr, "zunmount(%s,%s) running\r\n",
		zhp->zfs_name, dir); fflush(stderr);
	zfs_cmd_t zc = { "\0" };

	(void)strlcpy(zc.zc_name, zhp->zfs_name, sizeof(zc.zc_name));
	(void)strlcpy(zc.zc_value, dir, sizeof(zc.zc_value));

	ret = zfs_ioctl(zhp->zfs_hdl, ZFS_IOC_UNMOUNT, &zc);

	fprintf(stderr, "zunmount(%s,%s) returns %d\n",
		zhp->zfs_name, dir, ret);

	return ret;
}