
#ifndef	ZFS_BOOT_H_INCLUDED
#define	ZFS_BOOT_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif	/* __cplusplus */

/* Link data vdevs to virtual devices */
int zfs_boot_update_bootinfo(spa_t *spa);

#ifdef ZFS_BOOT
/* At boot time, get path from ZFSBootDevice */
int zfs_boot_get_path(char *, int);
#endif /* ZFS_BOOT */

#ifdef __cplusplus
} /* extern "C" */

#if 0
/* C++ struct, C uses opaque pointer reference */
typedef struct zfs_bootinfo {
	OSArray *info_array;
} zfs_bootinfo_t;
#endif

#ifdef ZFS_BOOT
/* Remainder is only needed for booting */

#include <IOKit/IOService.h>
bool zfs_boot_init(IOService *);
void zfs_boot_fini();

#pragma mark - ZFSBootDevice
#include <IOKit/storage/IOBlockStorageDevice.h>

class ZFSBootDevice : public IOBlockStorageDevice {
	OSDeclareDefaultStructors(ZFSBootDevice);
public:

	bool setDatasetName(const char *);

	virtual bool init(OSDictionary *);
	virtual void free();

	virtual IOReturn doSynchronizeCache(void);
	virtual IOReturn doAsyncReadWrite(IOMemoryDescriptor *,
	    UInt64, UInt64, IOStorageAttributes *,
	    IOStorageCompletion *);
	virtual UInt32 doGetFormatCapacities(UInt64 *,
	    UInt32) const;
	virtual IOReturn doFormatMedia(UInt64 byteCapacity);
	virtual IOReturn doEjectMedia();
	virtual char * getVendorString();
	virtual char * getProductString();
	virtual char * getRevisionString();
	virtual char * getAdditionalDeviceInfoString();
	virtual IOReturn reportWriteProtection(bool *);
	virtual IOReturn reportRemovability(bool *);
	virtual IOReturn reportMediaState(bool *, bool *);
	virtual IOReturn reportBlockSize(UInt64 *);
	virtual IOReturn reportEjectability(bool *);
	virtual IOReturn reportMaxValidBlock(UInt64 *);

	virtual IOReturn setWriteCacheState(bool enabled);
	virtual IOReturn    getWriteCacheState(bool *enabled);

private:
	/* These are declared class static to share across instances */
	static char vendorString[4];
	static char revisionString[4];
	static char infoString[12];
	/* These are per-instance */
	char *productString;
	bool isReadOnly;
};
#endif /* ZFS_BOOT */
#endif	/* __cplusplus */

#endif /* ZFS_BOOT_H_INCLUDED */
