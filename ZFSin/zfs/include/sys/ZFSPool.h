
#ifndef	ZFSPOOL_H_INCLUDED
#define	ZFSPOOL_H_INCLUDED

#ifdef __cplusplus
#include <IOKit/IOService.h>
#include <IOKit/storage/IOBlockStorageDevice.h>

#pragma mark - ZFSPool

class ZFSPool : public IOStorage {
	OSDeclareDefaultStructors(ZFSPool);

protected:
	virtual bool open(IOService *client,
	    IOOptionBits options, void *arg = 0);
	virtual void close(IOService *client,
	    IOOptionBits options);

	virtual bool handleOpen(IOService *client,
	    IOOptionBits options, void *access);
	virtual bool handleIsOpen(const IOService *client) const;
	virtual void handleClose(IOService *client,
	    IOOptionBits options);

	virtual bool isOpen(const IOService *forClient = 0) const;

	virtual bool init(OSDictionary *dict, spa_t *spa);

public:
	virtual void read(IOService *client, UInt64 byteStart,
	    IOMemoryDescriptor *buffer, IOStorageAttributes *attr,
	    IOStorageCompletion *completion);
	virtual void write(IOService *client, UInt64 byteStart,
	    IOMemoryDescriptor *buffer, IOStorageAttributes *attr,
	    IOStorageCompletion *completion);
	virtual IOReturn synchronizeCache(IOService * client);

	static ZFSPool * withServiceAndPool(IOService *, spa_t *);
private:
	spa_t *_spa;
};

/* C++ wrapper, C uses opaque pointer reference */
typedef struct spa_iokit {
	ZFSPool *proxy;
} spa_iokit_t;

extern "C" {
#endif /* __cplusplus */

/* C functions */
void spa_iokit_pool_proxy_destroy(spa_t *spa);
int spa_iokit_pool_proxy_create(spa_t *spa);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZFSPOOL_H_INCLUDED */
