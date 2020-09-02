﻿/*
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
  * Copyright (c) 2018 Julian Heuking <J.Heuking@beckhoff.com>
  */

#include "zfsinstaller.h"
#include <ctime>
#include <string>

extern "C" {
	#include <getopt.h>
	extern char* optarg;
}

// Usage:
//	zfsinstaller install [inf] [installFolder] (defaults to something like %ProgramFiles%\ZFS)
//	zfsinstaller uninstall [inf] (could default to something like %ProgramFiles%\ZFS\ZFSin.inf)
//  zfsinstaller trace -f Flags -l Levels -s SizeOfETLInMB -p AbsolutePathOfETL
//

const unsigned char ZFSIN_GUID[] = "c20c603c-afd4-467d-bf76-c0a4c10553df";
const unsigned char LOGGER_SESSION[] = "autosession\\zfsin_trace";

int session_exists(void) {
	char   command[256];

	sprintf_s(command, "logman query %s > nul", LOGGER_SESSION);

	int ret = system(command);
	if (ret == 0) {   // Session exists
		fprintf(stderr, "Logman session %s exists\n", LOGGER_SESSION);
	}
	return ret;
}

int zfs_log_session_delete(void) {
	char command[1024];

	int ret = session_exists();

	if (ret == 0) {  // Session exists
		sprintf_s(command, "cmd.exe /c \"logman delete %s > nul\"", LOGGER_SESSION);
		ret = system(command);
		if (ret != 0) {
			fprintf(stderr, "Error while deleting session %s\n", LOGGER_SESSION);
		}
		else {
			fprintf(stderr, "Logman session %s deleted successfully\n", LOGGER_SESSION);
		}
		return ret;
	}
	else {
		return 0; // Session does not exist ; We will pass success
	}
}

int validate_args(long long int flags, int levels, int size_in_mb, const char* etl_file) {
	if (flags < 0 || flags > 0xffffffff) {
		fprintf(stderr, "Valid input for flags should be in interval [0, 4294967295]\n");
		return 1;
	}

	if (levels < 0 || levels > 255) {
		fprintf(stderr, "Valid input for levels should be in interval [0, 255]\n");
		return 2;
	}

	if (!strcmp(etl_file, "") || !strstr(etl_file, ".etl")) {
		fprintf(stderr, "Etl file path/name is incorrect\n");
		return 3;
	}

	if (size_in_mb <= 0) {
		fprintf(stderr, "Size of etl should be greater than 0\n");
		return 4;
	}
	return 0;
}

int move_file(const char *etl_file) {
	char move_etl[1024];
	time_t rawtime;
	struct tm timeinfo;
	char buffer[25];

	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	strftime(buffer, sizeof(buffer), "_%Y%m%d%H%M%S", &timeinfo);

	strcpy_s(move_etl, etl_file);
	char* etl = strstr(move_etl, ".etl");
	if (etl)
		etl[0] = 0;

	strcat_s(move_etl, buffer);
	strcat_s(move_etl, ".etl");

	if (0 == rename(etl_file, move_etl)) {
		fprintf(stderr, "%s already exists\n", etl_file);
		fprintf(stderr, "%s has been renamed to %s\n", etl_file, move_etl);
		return 0;
	}
	else {
		fprintf(stderr, "Error while renaming the file %s\n", etl_file);
		return 1;
	}
}

int ArgParser(int argc, char **argv, long long int &flags, int &levels, int &size_in_mb, std::string &etl_file) {
	int option_index = 0;
	while ((option_index = getopt(argc, argv, "l:f:s:p:")) != -1) {
		switch (option_index) {
		case 'p':
			etl_file = std::string(optarg);
			break;
		case 'l':
			levels = atoi(optarg);
			break;
		case 'f':
			flags = atoll(optarg);
			break;
		case 's':
			size_in_mb = atoi(optarg);
			break;
		default:
			return 1;
		}
	}
	return 0;
}

int zfs_log_session_create(int argc, char** argv) {
	long long int flags = -1;
	int levels = -1;
	int size_in_mb = -1;
	std::string etl_file;
	char command[1024];
	int ret;

	ret = ArgParser(argc, argv, flags, levels, size_in_mb, etl_file);
	if (ret) {
		fprintf(stderr, "One or more arguments provided is incorrect\n");
		printUsage();
		return ret;
	}

	if (validate_args(flags, levels, size_in_mb, etl_file.c_str())) {
		fprintf(stderr, "Please check the provided values for the arguments\n");
		printUsage();
		return 1;
	}

	if (0 != session_exists()) { // If Session does not exist
		if (GetFileAttributesA(etl_file.c_str()) != INVALID_FILE_ATTRIBUTES) { // ETL EXISTS
			move_file(etl_file.c_str());
		}

		sprintf_s(command, "cmd.exe /c \"logman create trace %s -p {%s} %lld %d -nb 10 10 -bs 10 -mode Circular -max %d -o \"%s\"\" > nul",
			LOGGER_SESSION, ZFSIN_GUID, flags, levels, size_in_mb, etl_file.c_str());

		ret = system(command);
		if (ret != 0) {
			fprintf(stderr, "There is an issue creating the session %s\n", LOGGER_SESSION);
		}
		return ret;
	}
	return 0;
}


int main(int argc, char* argv[])
{
	if (argc <= 2) {
		fprintf(stderr, "too few arguments \n");
		printUsage();
		return ERROR_BAD_ARGUMENTS;
	}
	if (argc > 10) {
		fprintf(stderr, "too many arguments \n");
		printUsage();
		return ERROR_BAD_ARGUMENTS;
	}

	if (strcmp(argv[1], "install") == 0) {
		zfs_install(argv[2]);
		fprintf(stderr, "Installation done.");
	}
	else if (strcmp(argv[1], "uninstall") == 0) {
		int ret = zfs_uninstall(argv[2]);
		if (0 == ret) {
			return zfs_log_session_delete();
		}
		return ret;
	}
	else if (strcmp(argv[1], "trace") == 0) {
		return zfs_log_session_create(argc - 1, &argv[1]);
	}
	else {
		fprintf(stderr, "unknown argument %s\n", argv[1]);
		printUsage();
		return ERROR_BAD_ARGUMENTS;
	}
	return 0;
}

void printUsage() {
	fprintf(stderr, "Usage:\n\n");
	fprintf(stderr, "Install driver per INF DefaultInstall section:\n");
	fprintf(stderr, "zfsinstaller install inf_path\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Uninstall driver per INF DefaultUninstall section:\n");
	fprintf(stderr, "zfsinstaller uninstall inf_path\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "zfsinstaller trace -f Flags -l Levels -s SizeOfETLInMB -p AbsolutePathOfETL\n");
	fprintf(stderr, "Valid inputs for above arguments are as follows:\n");
	fprintf(stderr, "Flags             Should be in interval [0, 4294967295]\n");
	fprintf(stderr, "Levels            Should be in interval [0, 255]\n");
	fprintf(stderr, "SizeOfETLInMB     (Greater than 0)\n");
	fprintf(stderr, "AbsolutePathOfETL (Absolute Path including the Etl file name)\n");
}

DWORD zfs_install(char *inf_path) {

	DWORD error = 0;
	// 128+4	If a reboot of the computer is necessary, ask the user for permission before rebooting.
	
	error = executeInfSection("ZFSin_Install 128 ", inf_path);
	
	// Start driver service if not already running
	char serviceName[] = "ZFSin";
	if (!error)
		error = startService(serviceName);
	else
		fprintf(stderr, "Installation failed, skip starting the service");

	if (!error)
		error = installRootDevice(inf_path);

	return error;	
}

DWORD zfs_uninstall(char *inf_path)
{
	DWORD ret = 0;

	ret = send_zfs_ioc_unregister_fs();

	Sleep(2000);

	// 128+2	Always ask the users if they want to reboot.
	if (ret == 0)
		ret = executeInfSection("DefaultUninstall 128 ", inf_path);

	if (ret == 0)
		ret = uninstallRootDevice(inf_path);

	return ret;
}


DWORD executeInfSection(const char *cmd, char *inf_path) {

#ifdef _DEBUG
	system("sc query ZFSin");
	fprintf(stderr, "\n\n");
#endif
	
	DWORD error = 0;

	size_t len = strlen(cmd) + strlen(inf_path) + 1;
	size_t sz = 0;
	char buf[MAX_PATH];
	wchar_t wc_buf[MAX_PATH];

	sprintf_s(buf, "%s%s", cmd, inf_path);
	fprintf(stderr, "%s\n", buf);

	mbstowcs_s(&sz, wc_buf, len, buf, MAX_PATH);

	InstallHinfSection(
		NULL,
		NULL,
		wc_buf,
		0
	);


#ifdef _DEBUG
	system("sc query ZFSin");
#endif
	
	return error;
	// if we want to have some more control on installation, we need to get
	// a bit deeper into the setupapi, something like the following...

	/*HINF inf = SetupOpenInfFile(
		L"C:\\master_test\\ZFSin\\ZFSin.inf",//PCWSTR FileName,
		NULL,//PCWSTR InfClass,
		INF_STYLE_WIN4,//DWORD  InfStyle,
		0//PUINT  ErrorLine
	);

	if (!inf) {
		std::cout << "SetupOpenInfFile failed, err " << GetLastError() << "\n";
		return -1;
	}


	int ret = SetupInstallFromInfSection(
		NULL, //owner
		inf, //inf handle
		L"DefaultInstall",
		SPINST_ALL, //flags
		NULL, //RelativeKeyRoot
		NULL, //SourceRootPath
		SP_COPY_NEWER_OR_SAME | SP_COPY_IN_USE_NEEDS_REBOOT, //CopyFlags
		NULL, //MsgHandler
		NULL, //Context
		NULL, //DeviceInfoSet
		NULL //DeviceInfoData
	);

	if (!ret) {
		std::cout << "SetupInstallFromInfSection failed, err " << GetLastError() << "\n";
		return -1;
	}

	SetupCloseInfFile(inf);*/
}

DWORD startService(char* serviceName)
{
	DWORD error = 0;
	SC_HANDLE servMgrHdl;
	SC_HANDLE zfsServHdl;

	servMgrHdl = OpenSCManager(NULL, NULL, GENERIC_READ | GENERIC_EXECUTE);

	if (!servMgrHdl) {
		fprintf(stderr, "OpenSCManager failed, error %d\n", GetLastError());
		error = GetLastError();
		goto End;
	}

	zfsServHdl = OpenServiceA(servMgrHdl, serviceName, GENERIC_READ | GENERIC_EXECUTE);

	if (!zfsServHdl) {
		fprintf(stderr, "OpenServiceA failed, error %d\n", GetLastError());
		error = GetLastError();
		goto CloseMgr;
	}

	if (!StartServiceA(zfsServHdl, NULL, NULL)) {
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
			fprintf(stderr, "Service is already running\n");
		} else {
			fprintf(stderr, "StartServiceA failed, error %d\n", GetLastError());
			error = GetLastError();
			goto CloseServ;
		}
	}

CloseServ:
	CloseServiceHandle(zfsServHdl);
CloseMgr:
	CloseServiceHandle(servMgrHdl);
End:
	return error;
}

#define ZFSIOCTL_TYPE 40000

DWORD send_zfs_ioc_unregister_fs(void)
{
	HANDLE g_fd = CreateFile(L"\\\\.\\ZFS", GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, 0, NULL);

	DWORD bytesReturned;

	if (g_fd == INVALID_HANDLE_VALUE) {
		printf("Unable to open ZFS devnode, already uninstalled?\n");
		return 0;
	}

	// We use bytesReturned to hold "zfs_module_busy".
	BOOL ret = DeviceIoControl(
		g_fd,
		CTL_CODE(ZFSIOCTL_TYPE, 0x8E2, METHOD_NEITHER, FILE_ANY_ACCESS),
		NULL,
		0,
		NULL,
		0,
		&bytesReturned,
		NULL
		);

	CloseHandle(g_fd);

	if (!ret) return (1);

	if (bytesReturned != 0) {
		fprintf(stderr, "ZFS: Unable to uninstall until all pools are exported: %lu pool(s)\r\n", bytesReturned);
		return (2);
	}

	return (0);
}

#include <strsafe.h>
#include <cfgmgr32.h>
#include <newdev.h>

#define ZFS_ROOTDEV "Root\\ZFSin"
// DevCon uses LoadLib() - but lets just static link
#pragma comment(lib, "Newdev.lib")

HDEVINFO openDeviceInfo(char *inf, GUID *ClassGUID, char *ClassName, int namemax)
{
	HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
	char InfPath[MAX_PATH];

	// Inf must be a full pathname
	if (GetFullPathNameA(inf, MAX_PATH, InfPath, NULL) >= MAX_PATH) {
		// inf pathname too long
		goto final;
	}

	// Use the INF File to extract the Class GUID.
	if (!SetupDiGetINFClassA(InfPath, ClassGUID, ClassName, sizeof(ClassName) / sizeof(ClassName[0]), 0)) {
		goto final;
	}

	// Create the container for the to-be-created Device Information Element.
	DeviceInfoSet = SetupDiCreateDeviceInfoList(ClassGUID, 0);
	if (DeviceInfoSet == INVALID_HANDLE_VALUE) {
		goto final;
	}

	return DeviceInfoSet;

final:
	return NULL;
}



DWORD installRootDevice(char *inf)
{
	HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
	SP_DEVINFO_DATA DeviceInfoData;
	char hwIdList[LINE_LEN + 4];
	GUID ClassGUID;
	char ClassName[MAX_CLASS_NAME_LEN];
	int failcode = 12;

	DWORD flags = INSTALLFLAG_FORCE;
	BOOL reboot = FALSE;

	DeviceInfoSet = openDeviceInfo(inf, &ClassGUID, ClassName, MAX_CLASS_NAME_LEN);

	ZeroMemory(hwIdList, sizeof(hwIdList));
	if (FAILED(StringCchCopyA(hwIdList, LINE_LEN, ZFS_ROOTDEV))) {
		goto final;
	}

	// Now create the element.
	// Use the Class GUID and Name from the INF file.
	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	if (!SetupDiCreateDeviceInfoA(DeviceInfoSet,
		ClassName,
		&ClassGUID,
		NULL,
		0,
		DICD_GENERATE_ID,
		&DeviceInfoData)) {
		goto final;
	}

	// Add the HardwareID to the Device's HardwareID property.
	if (!SetupDiSetDeviceRegistryPropertyA(DeviceInfoSet,
		&DeviceInfoData,
		SPDRP_HARDWAREID,
		(LPBYTE)hwIdList,
		(DWORD) (strlen(hwIdList) + 1 + 1) * sizeof(char) )) {
		goto final;
	}

	// Transform the registry element into an actual devnode
	// in the PnP HW tree.
	if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE,
		DeviceInfoSet,
		&DeviceInfoData)) {
		goto final;
	}

	failcode = 0;

	// According to devcon we also have to Update now as well.
	UpdateDriverForPlugAndPlayDevicesA(NULL, ZFS_ROOTDEV, inf, flags, &reboot);

	if (reboot) printf("Windows indicated a Reboot is required.\n");

final:

	if (DeviceInfoSet != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	}
	printf("%s: exit %d:0x%x\n", __func__, failcode, failcode);

	return failcode;
}

DWORD uninstallRootDevice(char *inf)
{
	int failcode = 13;
	HDEVINFO DeviceInfoSet = INVALID_HANDLE_VALUE;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD DataT;
	char *p, *buffer = NULL;
	DWORD buffersize = 0;

	printf("%s: \n", __func__);

	DeviceInfoSet = SetupDiGetClassDevs(NULL, // All Classes
		0, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT); // All devices present on system
	if (DeviceInfoSet == INVALID_HANDLE_VALUE)
		goto final;

	printf("%s: looking for device rootnode to remove...\n", __func__);

	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	for (int i = 0; SetupDiEnumDeviceInfo(DeviceInfoSet, i, &DeviceInfoData); i++)
	{
		// Call once to get buffersize
		while (!SetupDiGetDeviceRegistryPropertyA(
			DeviceInfoSet,
			&DeviceInfoData,
			SPDRP_HARDWAREID,
			&DataT,
			(PBYTE)buffer,
			buffersize,
			&buffersize)) {

			if (GetLastError() == ERROR_INVALID_DATA) {
				// May be a Legacy Device with no HardwareID. Continue.
				break;
			} else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				// We need to change the buffer size.
				if (buffer)
					free(buffer);
				buffer = (char *)malloc(buffersize);
				if (buffer) ZeroMemory(buffer, buffersize);
			} else {
				// Unknown Failure.
				goto final;
			}
		}

		if (GetLastError() == ERROR_INVALID_DATA)
			continue;

		// Compare each entry in the buffer multi-sz list with our HardwareID.
		for (p = buffer; *p && (p < &buffer[buffersize]); p += strlen(p) + sizeof(char)) {
			//printf("%s: comparing '%s' with '%s'\n", __func__, "ROOT\\ZFSin", p);
			if (!_stricmp(ZFS_ROOTDEV, p)) {

				printf("%s: device found, removing ... \n", __func__);

				// Worker function to remove device.
				if (SetupDiCallClassInstaller(DIF_REMOVE,
						DeviceInfoSet,
						&DeviceInfoData)) {
						failcode = 0;
					}
					break;
			}
		}

		if (buffer) free(buffer);
		buffer = NULL;
		buffersize = 0;
	}

final:

	if (DeviceInfoSet != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	}
	printf("%s: exit %d:0x%x\n", __func__, failcode, failcode);

	return failcode;
}

#if 0




	ZeroMemory(hwIdList, sizeof(hwIdList));
	if (FAILED(StringCchCopyA(hwIdList, LINE_LEN, "ROOT\\ZFSin"))) {
			goto final;
	}

	printf("%s: CchCopy\n", __func__);

	// Now create the element.
	// Use the Class GUID and Name from the INF file.
	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	if (!SetupDiCreateDeviceInfoA(DeviceInfoSet,
		ClassName,
		&ClassGUID,
		NULL,
		0,
		DICD_GENERATE_ID,
		&DeviceInfoData)) {
		goto final;
	}

	printf("%s: SetupDiCreateDeviceInfoA\n", __func__);

	rmdParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	rmdParams.ClassInstallHeader.InstallFunction = DIF_REMOVE;
	rmdParams.Scope = DI_REMOVEDEVICE_GLOBAL;
	rmdParams.HwProfile = 0;
	if (!SetupDiSetClassInstallParamsA(DeviceInfoSet, &DeviceInfoData, &rmdParams.ClassInstallHeader, sizeof(rmdParams)) ||
		!SetupDiCallClassInstaller(DIF_REMOVE, DeviceInfoSet, &DeviceInfoData)) {

		// failed to invoke DIF_REMOVE
		failcode = 14;
		goto final;
	} 

	failcode = 0;

final:
	if (DeviceInfoSet != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(DeviceInfoSet);
	}
	printf("%s: exit %d:0x%x\n", __func__, failcode, failcode);
	return failcode;
}
#endif
