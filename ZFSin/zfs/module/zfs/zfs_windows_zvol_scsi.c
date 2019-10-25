/****************************** Module Header ******************************\
* Module Name:  scsi.c
* Project:      CppWDKStorPortVirtualMiniport
*
* Copyright (c) Microsoft Corporation.
* 
* a.       ScsiExecuteMain()
* Handles SCSI SRBs with opcodes needed to support file system operations by 
* calling subroutines. Fails SRBs with other opcodes.
* Note: In a real-world virtual miniport, it may be necessary to handle other opcodes.
* 
* b.      ScsiOpInquiry()
* Handles Inquiry, including creating a new LUN as needed.
* 
* c.       ScsiOpVPD()
* Handles Vital Product Data.
* 
* d.      ScsiOpRead()
* Beginning of a SCSI Read operation.
* 
* e.      ScsiOpWrite()
* Beginning of a SCSI Write operation.
* 
* f.        ScsiReadWriteSetup()
* Sets up a work element for SCSI Read or Write and enqueues the element.
* 
* g.       ScsiOpReportLuns()
* Handles Report LUNs.
* 
*
* This source is subject to the Microsoft Public License.
* See http://www.microsoft.com/opensource/licenses.mspx#Ms-PL.
* All other rights reserved.
* 
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
* EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
* WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
\***************************************************************************/     

#include <sys/debug.h>
#include <ntddk.h>
#include <storport.h>
//#include <scsiwmi.h>
//#include <initguid.h>
//#include <wmistr.h>
//#include <wdf.h>
//#include <hbaapi.h>
#include <sys/wzvol.h>
//#include <sys/wzvolwmi.h>

#pragma warning(push)
#pragma warning(disable : 4204)                       /* Prevent C4204 messages from stortrce.h. */
#include <stortrce.h>
#pragma warning(pop)

//#include "trace.h"
//#include "scsi.tmh"

#include <sys/zvol.h>

// Verbose SCSI output
//#undef dprintf
//#define dprintf

/*
 * We have a list of ZVOLs, and we receive incoming (Target, Lun) requests that needs to be mapped
 * to the correct "zv" ptr. As there appears to be a upper limit on the number of Targets we can
 * have, we use a static index list of zv ptrs. We might need to enhance this one day if people
 * create more ZVOLs than Storports max targets.
 *
 * We currently only use LUN==0. In future we could look at changing this.
 */

static zvol_state_t *zv_targets[WZOL_MAX_TARGETS] = { NULL };

int wzvol_assign_targetid(zvol_state_t *zv)
{
	void *empty = NULL;

	for (int i = 0; i < WZOL_MAX_TARGETS; i++) {
		if (atomic_cas_ptr(&zv_targets[i], NULL, zv) == NULL) {
			zv->zv_target_id = i;
			zv->zv_lun_id = 0;
			return 1;
		}
	}

	dprintf("ZFS: Unable to assign targetid - out of room, increase WZOL_MAX_TARGETS\n");
	ASSERT("Unable to assign targetid - out of room, increase WZOL_MAX_TARGETS");
	return 0;
}

static inline zvol_state_t *wzvol_find_target(uint8_t targetid, uint8_t lun)
{
	ASSERT(targetid < WZOL_MAX_TARGETS);
	if (targetid >= WZOL_MAX_TARGETS) return NULL;
	if (lun != 0) return NULL;
	return zv_targets[targetid];
}

void wzvol_clear_targetid(uint8_t targetid)
{
	ASSERT(targetid < WZOL_MAX_TARGETS);
	if (targetid < WZOL_MAX_TARGETS)
		zv_targets[targetid] = NULL;
}

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiExecuteMain(
                __in pHW_HBA_EXT          pHBAExt,    // Adapter device-object extension from StorPort.
                __in PSCSI_REQUEST_BLOCK  pSrb,
                __in PUCHAR               pResult
               )
{
    pHW_LU_EXTENSION pLUExt;
    UCHAR            status = SRB_STATUS_INVALID_REQUEST;

   dprintf("ScsiExecute: pSrb = 0x%p, CDB = 0x%x Path: %x TID: %x Lun: %x\n",
                      pSrb, pSrb->Cdb[0], pSrb->PathId, pSrb->TargetId, pSrb->Lun);

    *pResult = ResultDone;

    // For testing, return an error when the kernel debugger has set a flag.

    if (
        pHBAExt->LUNInfoArray[pSrb->Lun].bIODontUse   // No SCSI I/O to this LUN?
          &&
        SCSIOP_REPORT_LUNS!=pSrb->Cdb[0]              //   and not Report LUNs (which will be allowed)?
       ) {
        goto Done;
    }

    pLUExt = StorPortGetLogicalUnit(pHBAExt,          // Get the LU extension from StorPort.
                                    pSrb->PathId,
                                    pSrb->TargetId,
                                    pSrb->Lun 
                                   );

    if (!pLUExt) {
        dprintf( "Unable to get LUN extension for device %d:%d:%d\n",
                   pSrb->PathId, pSrb->TargetId, pSrb->Lun);

        status = SRB_STATUS_NO_DEVICE;
        goto Done;
    }

    // Test to get failure of I/O to this LUN on this path or on any path, except for Report LUNs.
    // Flag(s) to be set by kernel debugger. 

    if (
        (pLUExt->bIsMissing || (pLUExt->pLUMPIOExt && pLUExt->pLUMPIOExt->bIsMissingOnAnyPath)) 
          && 
        SCSIOP_REPORT_LUNS!=pSrb->Cdb[0]
       ) {
        status = SRB_STATUS_NO_DEVICE;
        goto Done;
    }

    // Handle sufficient opcodes to support a LUN suitable for a file system. Other opcodes are failed.

    switch (pSrb->Cdb[0]) {

        case SCSIOP_TEST_UNIT_READY:
        case SCSIOP_SYNCHRONIZE_CACHE:
        case SCSIOP_START_STOP_UNIT:
        case SCSIOP_VERIFY:
            status = SRB_STATUS_SUCCESS;
            break;

        case SCSIOP_INQUIRY:
            status = ScsiOpInquiry(pHBAExt, pLUExt, pSrb);
            break;

        case SCSIOP_READ_CAPACITY:
            status = ScsiOpReadCapacity(pHBAExt, pLUExt, pSrb);
            break;

        case SCSIOP_READ:
            status = ScsiOpRead(pHBAExt, pLUExt, pSrb, pResult);
            break;

        case SCSIOP_WRITE:
            status = ScsiOpWrite(pHBAExt, pLUExt, pSrb, pResult);
            break;

        case SCSIOP_MODE_SENSE:
            status = ScsiOpModeSense(pHBAExt, pLUExt, pSrb);
            break;

        case SCSIOP_REPORT_LUNS:                      
            status = ScsiOpReportLuns(pHBAExt, pLUExt, pSrb);
            break;

        default:
            status = SRB_STATUS_INVALID_REQUEST;
            break;

    } // switch (pSrb->Cdb[0])

Done:
    return status;
}                                                     // End ScsiExecuteMain.

/**************************************************************************************************/     
/*                                                                                                */     
/* Find an MPIO-collecting LUN object for the supplied (new) LUN, or allocate one.                */     
/*                                                                                                */     
/**************************************************************************************************/     
pHW_LU_EXTENSION_MPIO
ScsiGetMPIOExt(
               __in pHW_HBA_EXT          pHBAExt,     // Adapter device-object extension from StorPort.
               __in pHW_LU_EXTENSION     pLUExt,      // LUN device-object extension from StorPort.
               __in PSCSI_REQUEST_BLOCK  pSrb
              )
{
    pHW_LU_EXTENSION_MPIO pLUMPIOExt = NULL;          // Prevent C4701.
#if defined(_AMD64_)
    KLOCK_QUEUE_HANDLE    LockHandle, 
                          LockHandle2;
#else
    KIRQL                 SaveIrql,
                          SaveIrql2;
#endif
    PLIST_ENTRY           pNextEntry;

#if defined(_AMD64_)
    KeAcquireInStackQueuedSpinLock(&pHBAExt->pwzvolDrvObj->MPIOExtLock, &LockHandle);
#else
    KeAcquireSpinLock(&pHBAExt->pwzvolDrvObj->MPIOExtLock, &SaveIrql);
#endif

    for (                                             // Go through linked list of MPIO-collecting LUN objects.
         pNextEntry = pHBAExt->pwzvolDrvObj->ListMPIOExt.Flink;
         pNextEntry != &pHBAExt->pwzvolDrvObj->ListMPIOExt;
         pNextEntry = pNextEntry->Flink
        ) {
        pLUMPIOExt = CONTAINING_RECORD(pNextEntry, HW_LU_EXTENSION_MPIO, List);

        if (pSrb->PathId==pLUMPIOExt->ScsiAddr.PathId // Same SCSI address?
              &&
            pSrb->TargetId==pLUMPIOExt->ScsiAddr.TargetId
              &&
            pSrb->Lun==pLUMPIOExt->ScsiAddr.Lun
           ) {
            break;
        }
    }

    if (pNextEntry==&pHBAExt->pwzvolDrvObj->ListMPIOExt) { // No match? That is, is this to be a new MPIO LUN extension?
        pLUMPIOExt = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(HW_LU_EXTENSION_MPIO), MP_TAG_GENERAL);

        if (!pLUMPIOExt) {
			dprintf("Failed to allocate HW_LU_EXTENSION_MPIO\n");

            goto Done;
        }

        RtlZeroMemory(pLUMPIOExt, sizeof(HW_LU_EXTENSION_MPIO));

        pLUMPIOExt->ScsiAddr.PathId   = pSrb->PathId;
        pLUMPIOExt->ScsiAddr.TargetId = pSrb->TargetId;
        pLUMPIOExt->ScsiAddr.Lun      = pSrb->Lun;

        KeInitializeSpinLock(&pLUMPIOExt->LUExtMPIOLock);

        InitializeListHead(&pLUMPIOExt->LUExtList);

        //ScsiAllocDiskBuf(pHBAExt, &pLUMPIOExt->pDiskBuf, &pLUExt->MaxBlocks);

        if (!pLUMPIOExt->pDiskBuf) {         
			dprintf("Failed to allocate DiskBuf\n");
            ExFreePoolWithTag(pLUMPIOExt, MP_TAG_GENERAL);
            pLUMPIOExt = NULL;

            goto Done;
        }

        InsertTailList(&pHBAExt->pwzvolDrvObj->ListMPIOExt, &pLUMPIOExt->List);

        pHBAExt->pwzvolDrvObj->DrvInfoNbrMPIOExtObj++;
    }
    else {
        pLUExt->MaxBlocks = (USHORT)(pHBAExt->pwzvolDrvObj->wzvolRegInfo.PhysicalDiskSize / MP_BLOCK_SIZE);
    }

Done:
    if (pLUMPIOExt) {                                 // Have an MPIO-collecting LUN object?
        // Add the real LUN to the MPIO-collecting LUN object.

#if defined(_AMD64_)
        KeAcquireInStackQueuedSpinLock(&pLUMPIOExt->LUExtMPIOLock, &LockHandle2);
#else
        KeAcquireSpinLock(&pLUMPIOExt->LUExtMPIOLock, &SaveIrql2);
#endif

        pLUExt->pLUMPIOExt = pLUMPIOExt;
        pLUExt->pDiskBuf = pLUMPIOExt->pDiskBuf;

        InsertTailList(&pLUMPIOExt->LUExtList, &pLUExt->MPIOList);
        pLUMPIOExt->NbrRealLUNs++;

#if defined(_AMD64_)
        KeReleaseInStackQueuedSpinLock(&LockHandle2); // Release serialization on MPIO-collecting LUN object.
#else
        KeReleaseSpinLock(&pLUMPIOExt->LUExtMPIOLock, SaveIrql2);
#endif
    }

#if defined(_AMD64_)
    KeReleaseInStackQueuedSpinLock(&LockHandle);      // Release the linked list of MPIO collector objects.
#else
    KeReleaseSpinLock(&pHBAExt->pwzvolDrvObj->MPIOExtLock, SaveIrql);
#endif

    return pLUMPIOExt;
}                                                     // End ScsiGetMPIOExt.

UCHAR
ScsiOpInquiry(
	__in pHW_HBA_EXT          pHBAExt,      // Adapter device-object extension from StorPort.
	__in pHW_LU_EXTENSION     pLUExt,       // LUN device-object extension from StorPort.
	__in PSCSI_REQUEST_BLOCK  pSrb
)
{
	PINQUIRYDATA          pInqData = pSrb->DataBuffer;// Point to Inquiry buffer.
	UCHAR                 deviceType,
		status = SRB_STATUS_SUCCESS;
	PCDB                  pCdb;
	pHW_LU_EXTENSION_MPIO pLUMPIOExt;
#if defined(_AMD64_)
	KLOCK_QUEUE_HANDLE    LockHandle;
#else
	KIRQL                 SaveIrql;
#endif
	zvol_state_t *zv;

	dprintf("%s: Path: %d TID: %d Lun: %d\n", __func__,
		pSrb->PathId, pSrb->TargetId, pSrb->Lun);

	RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength);

	zv = wzvol_find_target(pSrb->TargetId, pSrb->Lun);

	if (zv == NULL) {
		pSrb->DataTransferLength = 0;
		status = SRB_STATUS_INVALID_LUN;
		goto done;
	}

	pCdb = (PCDB)pSrb->Cdb;

	if (1 == pCdb->CDB6INQUIRY3.EnableVitalProductData) {
		dprintf("Received VPD request for page 0x%x\n",
			pCdb->CDB6INQUIRY.PageCode);

		status = ScsiOpVPD(pHBAExt, pLUExt, pSrb);

		goto done;
	}

	pInqData->DeviceType = DISK_DEVICE;
	pInqData->RemovableMedia = FALSE;
	pInqData->CommandQueue = TRUE;

	RtlMoveMemory(pInqData->VendorId, pHBAExt->VendorId, 8);
	RtlMoveMemory(pInqData->ProductId, pHBAExt->ProductId, 16);
	RtlMoveMemory(pInqData->ProductRevisionLevel, pHBAExt->ProductRevision, 4);

	// Copy in the zvol name
	strlcpy(pInqData->ProductId, zv->zv_name, 16);

	//
	// Reply as valid LUN
	//

	if (GET_FLAG(pLUExt->LUFlags, LU_DEVICE_INITIALIZED)) {
		// This is an existing device.
		goto done;
	}

	pLUExt->DeviceType = DISK_DEVICE;
	pLUExt->TargetId = pSrb->TargetId;
	pLUExt->Lun = pSrb->Lun;

	SET_FLAG(pLUExt->LUFlags, LU_DEVICE_INITIALIZED);

done:
	return status;
}                                                     // End ScsiOpInquiry.


/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpVPD(
	__in pHW_HBA_EXT          pHBAExt,          // Adapter device-object extension from StorPort.
	__in pHW_LU_EXTENSION     pLUExt,           // LUN device-object extension from StorPort.
	__in PSCSI_REQUEST_BLOCK  pSrb
)
{
	UCHAR                  status;
	ULONG                  len;
	struct _CDB6INQUIRY3 * pVpdInquiry = (struct _CDB6INQUIRY3 *)&pSrb->Cdb;;

	ASSERT(pLUExt != NULL);
	ASSERT(pSrb->DataTransferLength > 0);

	if (0 == pSrb->DataTransferLength) {
		return SRB_STATUS_DATA_OVERRUN;
	}

	RtlZeroMemory((PUCHAR)pSrb->DataBuffer,           // Clear output buffer.
		pSrb->DataTransferLength);

	if (VPD_SUPPORTED_PAGES == pVpdInquiry->PageCode) { // Inquiry for supported pages?
		PVPD_SUPPORTED_PAGES_PAGE pSupportedPages;

		len = sizeof(VPD_SUPPORTED_PAGES_PAGE) + 8;

		if (pSrb->DataTransferLength < len) {
			return SRB_STATUS_DATA_OVERRUN;
		}

		pSupportedPages = pSrb->DataBuffer;             // Point to output buffer.

		pSupportedPages->DeviceType = DISK_DEVICE;
		pSupportedPages->DeviceTypeQualifier = 0;
		pSupportedPages->PageCode = VPD_SERIAL_NUMBER;
		pSupportedPages->PageLength = 8;                // Enough space for 4 VPD values.
		pSupportedPages->SupportedPageList[0] =         // Show page 0x80 supported.
			VPD_SERIAL_NUMBER;
		pSupportedPages->SupportedPageList[1] =         // Show page 0x83 supported.
			VPD_DEVICE_IDENTIFIERS;

		status = SRB_STATUS_SUCCESS;


	} else if (VPD_SERIAL_NUMBER == pVpdInquiry->PageCode) {   // Inquiry for serial number?

		PVPD_SERIAL_NUMBER_PAGE pVpd;

		len = sizeof(VPD_SERIAL_NUMBER_PAGE) + 8 + 32;
		if (pSrb->DataTransferLength < len) {
			return SRB_STATUS_DATA_OVERRUN;
		}

		pVpd = pSrb->DataBuffer;                        // Point to output buffer.

		pVpd->DeviceType = DISK_DEVICE;
		pVpd->DeviceTypeQualifier = 0;
		pVpd->PageCode = VPD_SERIAL_NUMBER;
		pVpd->PageLength = 8 + 32;

		if (pHBAExt->pwzvolDrvObj->wzvolRegInfo.bCombineVirtDisks) { // MPIO support?
			/* Generate a constant serial number. */
  //        sprintf((char *)pVpd->SerialNumber, "000%02d%03d0123456789abcdefghijABCDEFGHIJxx\n", 
  //                pLUExt->TargetId, pLUExt->Lun);
		} else {
			/* Generate a changing serial number. */
  //        sprintf((char *)pVpd->SerialNumber, "%03d%02d%03d0123456789abcdefghijABCDEFGHIJxx\n", 
  //                pHBAExt->pwzvolDrvObj->DrvInfoNbrMPHBAObj, pLUExt->TargetId, pLUExt->Lun);
		}

		dprintf(
			"ScsiOpVPD:  VPD Page: %d Serial No.: %s", pVpd->PageCode, (const char *)pVpd->SerialNumber);

		status = SRB_STATUS_SUCCESS;
	} else if (VPD_DEVICE_IDENTIFIERS == pVpdInquiry->PageCode) { // Inquiry for device ids?
		PVPD_IDENTIFICATION_PAGE pVpid;
		PVPD_IDENTIFICATION_DESCRIPTOR pVpidDesc;

#define VPIDNameSize 32
#define VPIDName     "PSSLUNxxx"

		len = sizeof(VPD_IDENTIFICATION_PAGE) + sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + VPIDNameSize;

		if (pSrb->DataTransferLength < len) {
			return SRB_STATUS_DATA_OVERRUN;
		}

		pVpid = pSrb->DataBuffer;                     // Point to output buffer.

		pVpid->PageCode = VPD_DEVICE_IDENTIFIERS;

		pVpidDesc =                                   // Point to first (and only) descriptor.
			(PVPD_IDENTIFICATION_DESCRIPTOR)pVpid->Descriptors;

		pVpidDesc->CodeSet = VpdCodeSetAscii;         // Identifier contains ASCII.
		pVpidDesc->IdentifierType =                   // 
			VpdIdentifierTypeFCPHName;

		if (pHBAExt->pwzvolDrvObj->wzvolRegInfo.bCombineVirtDisks) { // MPIO support?
			/* Generate a constant serial number. */
			sprintf((char *)pVpidDesc->Identifier, "000%02d%03d0123456789abcdefghij\n",
				pLUExt->TargetId, pLUExt->Lun);
		} else {
			/* Generate a changing serial number. */
			sprintf((char *)pVpidDesc->Identifier, "%03d%02d%03d0123456789abcdefghij\n",
				pHBAExt->pwzvolDrvObj->DrvInfoNbrMPHBAObj, pLUExt->TargetId, pLUExt->Lun);
		}

		pVpidDesc->IdentifierLength =                 // Size of Identifier.
			(UCHAR)strlen((const char *)pVpidDesc->Identifier) - 1;
		pVpid->PageLength =                           // Show length of remainder.
			(UCHAR)(FIELD_OFFSET(VPD_IDENTIFICATION_PAGE, Descriptors) +
				FIELD_OFFSET(VPD_IDENTIFICATION_DESCRIPTOR, Identifier) +
				pVpidDesc->IdentifierLength);

		dprintf("ScsiOpVPD:  VPD Page 0x83");

		status = SRB_STATUS_SUCCESS;
	} else {
		status = SRB_STATUS_INVALID_REQUEST;
		len = 0;
	}

	pSrb->DataTransferLength = len;

	return status;
}                                                     // End ScsiOpVPD().

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpReadCapacity(
                   __in pHW_HBA_EXT          pHBAExt, // Adapter device-object extension from StorPort.
                   __in pHW_LU_EXTENSION     pLUExt,  // LUN device-object extension from StorPort.
                   __in PSCSI_REQUEST_BLOCK  pSrb
                  )
{
    PREAD_CAPACITY_DATA  readCapacity = pSrb->DataBuffer;
    ULONG                maxBlocks,
                         blockSize;

    UNREFERENCED_PARAMETER(pHBAExt);
    UNREFERENCED_PARAMETER(pLUExt);

    ASSERT(pLUExt != NULL);

    RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength );

    // Claim 512-byte blocks (big-endian).
	// Ask ZVOL about block size
    //blockSize = MP_BLOCK_SIZE;
	zvol_state_t *zv;
	zv = wzvol_find_target(pSrb->TargetId, pSrb->Lun);

	if (zv == NULL) {
		pSrb->DataTransferLength = 0;
		return SRB_STATUS_INVALID_REQUEST;
	}

	blockSize = zv->zv_volblocksize;

    readCapacity->BytesPerBlock =
      (((PUCHAR)&blockSize)[0] << 24) |  (((PUCHAR)&blockSize)[1] << 16) |
      (((PUCHAR)&blockSize)[2] <<  8) | ((PUCHAR)&blockSize)[3];

	maxBlocks = zv->zv_volsize / blockSize;

	dprintf("Block Size: 0x%x Total Blocks: 0x%x\n", blockSize, maxBlocks);

    readCapacity->LogicalBlockAddress =
      (((PUCHAR)&maxBlocks)[0] << 24) | (((PUCHAR)&maxBlocks)[1] << 16) |
      (((PUCHAR)&maxBlocks)[2] <<  8) | ((PUCHAR)&maxBlocks)[3];

	return SRB_STATUS_SUCCESS;
}                                                     // End ScsiOpReadCapacity.

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpRead(
           __in pHW_HBA_EXT          pHBAExt,         // Adapter device-object extension from StorPort.
           __in pHW_LU_EXTENSION     pLUExt,          // LUN device-object extension from StorPort.
           __in PSCSI_REQUEST_BLOCK  pSrb,
           __in PUCHAR               pResult
          )
{
    UCHAR                        status;

    status = ScsiReadWriteSetup(pHBAExt, pLUExt, pSrb, ActionRead, pResult);

    return status;
}                                                     // End ScsiOpRead.

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpWrite(
            __in pHW_HBA_EXT          pHBAExt,        // Adapter device-object extension from StorPort.
            __in pHW_LU_EXTENSION     pLUExt,         // LUN device-object extension from StorPort.
            __in PSCSI_REQUEST_BLOCK  pSrb,
            __in PUCHAR               pResult
           )
{
    UCHAR                        status;

    status = ScsiReadWriteSetup(pHBAExt, pLUExt, pSrb, ActionWrite, pResult);

    return status;
}                                                     // End ScsiOpWrite.

/**************************************************************************************************/     
/*                                                                                                */     
/* This routine does the setup for reading or writing. The reading/writing could be effected      */     
/* here rather than in MpGeneralWkRtn, but in the general case MpGeneralWkRtn is going to be the  */     
/* place to do the work since it gets control at PASSIVE_LEVEL and so could do real I/O, could    */     
/* wait, etc, etc.                                                                                */     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiReadWriteSetup(
	__in pHW_HBA_EXT          pHBAExt, // Adapter device-object extension from StorPort.
	__in pHW_LU_EXTENSION     pLUExt,  // LUN device-object extension from StorPort.        
	__in PSCSI_REQUEST_BLOCK  pSrb,
	__in MpWkRtnAction        WkRtnAction,
	__in PUCHAR               pResult
)
{
	PCDB                         pCdb = (PCDB)pSrb->Cdb;
	ULONG                        startingSector,
		sectorOffset;
	USHORT                       numBlocks;
	pMP_WorkRtnParms             pWkRtnParms;

	ASSERT(pLUExt != NULL);

	*pResult = ResultDone;                            // Assume no queuing.

	pWkRtnParms =                                     // Allocate parm area for work routine.
		(pMP_WorkRtnParms)ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(MP_WorkRtnParms), MP_TAG_GENERAL);

	if (NULL == pWkRtnParms) {
		dprintf("ScsiReadWriteSetup Failed to allocate work parm structure\n");

		return SRB_STATUS_ERROR;
	}

	RtlZeroMemory(pWkRtnParms, sizeof(MP_WorkRtnParms));

	pWkRtnParms->pHBAExt = pHBAExt;
	pWkRtnParms->pLUExt = pLUExt;
	pWkRtnParms->pSrb = pSrb;
	pWkRtnParms->Action = ActionRead == WkRtnAction ? ActionRead : ActionWrite;

	pWkRtnParms->pQueueWorkItem = IoAllocateWorkItem((PDEVICE_OBJECT)pHBAExt->pDrvObj);

	if (NULL == pWkRtnParms->pQueueWorkItem) {
		dprintf("ScsiReadWriteSetup: Failed to allocate work item\n");

		ExFreePoolWithTag(pWkRtnParms, MP_TAG_GENERAL);

		return SRB_STATUS_ERROR;
	}

	// Queue work item, which will run in the System process.

	IoQueueWorkItem(pWkRtnParms->pQueueWorkItem, wzvol_GeneralWkRtn, DelayedWorkQueue, pWkRtnParms);

	*pResult = ResultQueued;                          // Indicate queuing.

	return SRB_STATUS_SUCCESS;
}                                                     // End ScsiReadWriteSetup.

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpModeSense(
                __in pHW_HBA_EXT          pHBAExt,    // Adapter device-object extension from StorPort.
                __in pHW_LU_EXTENSION     pLUExt,     // LUN device-object extension from StorPort.
                __in PSCSI_REQUEST_BLOCK  pSrb
               )
{
    UNREFERENCED_PARAMETER(pHBAExt);
    UNREFERENCED_PARAMETER(pLUExt);

    RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength);

    return SRB_STATUS_SUCCESS;
}

/**************************************************************************************************/     
/*                                                                                                */     
/**************************************************************************************************/     
UCHAR
ScsiOpReportLuns(                                     
                 __in __out pHW_HBA_EXT         pHBAExt,   // Adapter device-object extension from StorPort.
                 __in       pHW_LU_EXTENSION    pLUExt,    // LUN device-object extension from StorPort.
                 __in       PSCSI_REQUEST_BLOCK pSrb
                )
{
    UCHAR     status = SRB_STATUS_SUCCESS;
    PLUN_LIST pLunList = (PLUN_LIST)pSrb->DataBuffer; // Point to LUN list.
    ULONG     i, 
              GoodLunIdx;

    UNREFERENCED_PARAMETER(pLUExt);

    if (FALSE==pHBAExt->bReportAdapterDone) {         // This opcode will be one of the earliest I/O requests for a new HBA (and may be received later, too).
        wzvol_HwReportAdapter(pHBAExt);                   // WMIEvent test.

        wzvol_HwReportLink(pHBAExt);                      // WMIEvent test.

        wzvol_HwReportLog(pHBAExt);                       // WMIEvent test.

        pHBAExt->bReportAdapterDone = TRUE;
    }
	
	zvol_state_t *zv;

	zv = wzvol_find_target(pSrb->TargetId, pSrb->Lun);

	if (zv != NULL &&
		pSrb->PathId == 0 &&
		!pHBAExt->bDontReport) {

		RtlZeroMemory((PUCHAR)pSrb->DataBuffer, pSrb->DataTransferLength);

        pLunList->LunListLength[3] =                  // Set length needed for LUNs.
            (UCHAR)(8*pHBAExt->NbrLUNsperHBA);

        // Set the LUN numbers if there is enough room, and set only those LUNs to be reported.

        if (pSrb->DataTransferLength>=FIELD_OFFSET(LUN_LIST, Lun) + (sizeof(pLunList->Lun[0])*pHBAExt->NbrLUNsperHBA)) {
            for (i = 0, GoodLunIdx = 0; i < pHBAExt->NbrLUNsperHBA; i ++) {
                // LUN to be reported?
                if (FALSE==pHBAExt->LUNInfoArray[i].bReportLUNsDontUse) {
                    pLunList->Lun[GoodLunIdx][1] = (UCHAR)i;
                    GoodLunIdx++;
                }
            }
        }
    }

    return status;
}                                                     // End ScsiOpReportLuns.

VOID
wzvol_WkRtn(__in PVOID pWkParms)                          // Parm list pointer.
{
	pMP_WorkRtnParms          pWkRtnParms = (pMP_WorkRtnParms)pWkParms;
	pHW_HBA_EXT               pHBAExt = pWkRtnParms->pHBAExt;
	pHW_LU_EXTENSION          pLUExt = pWkRtnParms->pLUExt;
	PSCSI_REQUEST_BLOCK       pSrb = pWkRtnParms->pSrb;
	PCDB                      pCdb = (PCDB)pSrb->Cdb;
	ULONG                     startingSector,
		sectorOffset,
		lclStatus;
	PVOID                     pX = NULL;
	UCHAR                     status;

	zvol_state_t *zv;

	zv = wzvol_find_target(pSrb->TargetId, pSrb->Lun);

	if (zv == NULL) {
		status = SRB_STATUS_ERROR;
		goto Done;
	}

	startingSector = pCdb->CDB10.LogicalBlockByte3 |
		pCdb->CDB10.LogicalBlockByte2 << 8 |
		pCdb->CDB10.LogicalBlockByte1 << 16 |
		pCdb->CDB10.LogicalBlockByte0 << 24;

	sectorOffset = startingSector * zv->zv_volblocksize;

	dprintf("MpWkRtn Action: %X, starting sector: 0x%X, sector offset: 0x%X\n", pWkRtnParms->Action, startingSector, sectorOffset);
	dprintf("MpWkRtn pSrb: 0x%p, pSrb->DataBuffer: 0x%p\n", pSrb, pSrb->DataBuffer);

	// Note:  Obviously there's going to be a problem if pSrb->DataBuffer points to something in user space, since the correct user space
	//        is probably not that of the System process.  Less obviously, in the paging path at least, even an address in kernel space 
	//        proved not valid; that is, not merely not backed by real storage but actually not valid.  The reason for this behavior is
	//        still under investigation.  For now, in all cases observed, it has been found sufficient to get a new kernel-space address 
	//        to use.

	lclStatus = StorPortGetSystemAddress(pHBAExt, pSrb, &pX);

	if (STOR_STATUS_SUCCESS != lclStatus || !pX) {
		dprintf("MpWkRtn Failed to get system address for pSrb = 0x%p, pSrb->DataBuffer=0x%p, status = 0x%08x, pX = 0x%p\n",
			pSrb, pSrb->DataBuffer, lclStatus, pX);
		status = SRB_STATUS_ERROR;
		goto Done;
	}


	if (sectorOffset >= zv->zv_volsize) {      // Starting sector beyond the bounds?
		dprintf("%s: invalid starting sector: %d\n", __func__, startingSector);
		status = SRB_STATUS_INVALID_REQUEST;
		goto Done;
	}

	/* Call ZFS to read/write data */
	if (ActionRead == pWkRtnParms->Action) {           
		status = zvol_read_win(zv, sectorOffset, pSrb->DataTransferLength, pX);
	} else {                                           
		status = zvol_write_win(zv, sectorOffset, pSrb->DataTransferLength, pX);
	}

	if (status == 0)
		status = SRB_STATUS_SUCCESS;

Done:
	pSrb->SrbStatus = status;

	// Tell StorPort this action has been completed.

	StorPortNotification(RequestComplete, pHBAExt, pSrb);

	ExFreePoolWithTag(pWkParms, MP_TAG_GENERAL);      // Free parm list.
}                                                     // End MpWkRtn().


VOID
wzvol_GeneralWkRtn(
	__in PVOID           pDummy,           // Not used.
	__in PVOID           pWkParms          // Parm list pointer.
)
{
	pMP_WorkRtnParms        pWkRtnParms = (pMP_WorkRtnParms)pWkParms;

	UNREFERENCED_PARAMETER(pDummy);

	IoFreeWorkItem(pWkRtnParms->pQueueWorkItem);      // Free queue item.

	pWkRtnParms->pQueueWorkItem = NULL;               // Be neat.

	// If the next starts, it has to be stopped by a kernel debugger.

	while (pWkRtnParms->SecondsToDelay) {
		LARGE_INTEGER delay;

		delay.QuadPart = -10 * 1000 * 1000 * pWkRtnParms->SecondsToDelay;

		KeDelayExecutionThread(KernelMode, TRUE, &delay);
	}

	wzvol_WkRtn(pWkParms);                                // Do the actual work.
}                                                     // End MpGeneralWkRtn().

