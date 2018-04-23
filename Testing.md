
# IFSTEST.EXE

## Security

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     | SetDaclSecurityTest    |  |
|✅     | SetOwnerSecurityTest   |  |
|✅     | SetGroupSecurityTest   |  |
|✅     | SetSaclSecurityTest    |  |
|❌     | AuditOwnerSecurityTest | Prints nothing? |
|❌     | DirectoryTraverseTest  | Allows Dir create when shouldn't |


## OpenCreateGeneral

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       | FileSystemDeviceOpenTest | |
|✅     | FileFullPathCreationTest | |
|✅     | DirectoryFullPathCreationTest  | |
|✅     | FileRelativePathCreationTest  | |
|✅     | DirectoryRelativePathCreationTest  | |
|❌     | FileOpenByIDTest  | fails due to attributes mismatch? |
|❌     | NonDirectoryFileOpenTest  | Fails but STATUS expected is STATUS received? |
|❌     | OpenVolumeTest  | locking failure, should be exclusive |
|❌     | CreatePagingFileTest  | not yet supported |
|✅     | FileNameLengthTest  | |
|✅     | HFHTest  | |
|✅     | UnicodeOnDiskTest  | |
|✅     | CaseSensitiveTest  | |
|✅     | PreserveCaseTest  | |
|❌     | ShortFileNameTest  | Don't handle shortnames yet |
|✅     | ShareAccessTest  | |
|✅     | AlternateStreamTest  | |
|✅     | StreamShareTest  | |


## OpenCreateParameters

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     | OpenFileTest  | |
|✅     | OpenFileDirTest  | |
|✅     | CreateFileTest  | |
|✅     | CreateFileDirTest  | |
|✅     | OpenAlwaysFileTest  | |
|✅     | OpenAlwaysFileDirTest  | |
|✅     | OverwriteFileTest  | |
|✅     | OverwriteFileAllocTest  | |
|✅     | OverwriteFileAttrTest  | |
|✅     | OverwriteAlwaysAllocTest  | |
|✅     | OverwriteAlwaysAttrTest  |  |
|✅     | SupersedeFileTest  | |
|✅     | SupersedeFileAllocTest  | |
|✅     | SupersedeFileAttrTest  | |
|❌     | FileAllocationSizeTest  | Fails as allocsize is not zero |
|✅     | ExecuteAccessTest  | |
|❌     | ReadOnlyAttributeTest  | No file permissions yet |
|✅     | HiddenAttributeTest  | |
|✅     | SystemAttributeTest  | |
|✅     | ArchiveAttributeTest  | |
|✅     | NormalAttributeTest  | |
|✅     | DirectoryAttributeTest  | |


## CloseCleanupDelete

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       | VolumeUnlockOnCloseTest  | |
|❌     | UpdateOnCloseTest  | |
|❌     | UpdateOnCloseDirTest  | |
|✅     | TruncateOnCloseTest  | |
|❌     | DeleteOnLastCloseTest  | |
|❌     | TunnelingTest  | |


## VolumeInformation

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     | VolumeInformationTest  | |
|✅     | SizeInformationTest  | |
|✅     | DeviceInformationTest  | |
|✅     | AttributeInformationTest  | |


## FileInformation

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     | BasicInformationTest  | |
|✅     | StandardInformationTest  | pass but for allocationsize=0x3e4 |
|✅     | InternalInformationTest  | |
|❌     | EaInformationTest  | EA needs attention |
|✅     | NameInformationTest  | |
|❌     | AllInformationTest  | says filenames dont match when they do |
|❌     | AllocationInformationTest  | |
|❌     | ZeroAllocationInformationTest  | |
|       | CompressionInformationTest  | |
|       | DispositionInformationTest  | |
|✅     | EndOfFileInformationTest  | |
|❌     | LinkInformationTest  | |
|       | SimpleRenameInformationTest  | |
|❌     | ConflictingRenameInformationTest  | |
|☢     | AlternateNameInformationTest  | |
|❌     | FileNetworkOpenInformationTest  | 0x3e8 != 0x400 |
|❌     | StreamInformationTest  | Streams not implemented |
|❌     | StreamStandardInformationTest  | 〃 |
|❌     | HardLinkInformationTest  | 〃 |
|❌     | TimeStampTest  | Time disagrees |


## EaInformation

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |CreateEaInformationTest  | |
|       |SetEaInformationTest  | |
|       |SingleEaEntryTest  | |
|       |FullEaInformationTest  | |
|       |ListEaInformationTest  | |
|       |IndexEaInformationTest  | |



## DirectoryInformation

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     |FileNameDirectoryInformationTest  | |
|❌     |FileDirectoryInformationTest  | Off by 1ms |
|❌     |FullDirectoryInformationTest  | EAsize wrong |
|✅     |BothDirectoryInformationTest  | |


## FileLocking

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |LockSharedExTest  | |
|       |UnlockRangeTest  | |
|       |LockOverlapTest  | |
|       |LockRangeTest  | |
|       |LockFailImmediateTest  | |
|       |LockOverlappedTest  | |
|       |UnlockAllTest  | |
|       |UnlockRangeOnCloseTest  | |
|       |LockKeyTest  | |


## OpLocks

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |OplockBreakItoIITest  | |
|       |OplockBreakIandIIOnCloseTest  | |
|       |OplockIIWriteBreakingTest  | |
|       |BatchOplocksTest  | |
|       |BreakNotifyTest  | |
|       |FilterOplockTest  | |
|       |CompleteImmediatelyTest  | |
|       |OplockReadBreakItoIITest  | |
|       |OplockLevel1Test  | |
|       |OplockSetInfoBreakTest  | |
|       |LockOplockBreakTest  | |


## ChangeNotification

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     |NotificationDeleteTest  | |
|✅     |NotificationCloseTest  | |
|❌     |NotificationFilenameTest  | |
|❌     |NotificationNonDirectoryTest  | Last Write notify missing |
|❌     |NotificationSecurityTest  | cmd blocks |
|❌     |NotificationCleanupAttribTest  | 〃 |


## DeviceControl

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|❌     |DeviceIoControlTest  | timeout |


## FileSystemControlGeneral

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|❌     |GetRetrievalPointersTest  | Probably wont implement |
|       |SetCompressionTest  | ZFS claims not to do compression |
|       |GetVolumeBitmapTest  | Not implemented |
|❌     |MoveFileTest  | retrievea pointers ? |
|       |AllowExtendedDASDTest  | |


## ReadWrite

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|❌     |ReadWriteTest  | async write changed file position |
|✅     |ReadWriteCoherencyTest  | |
|❌     |AppendDataTest  | read pattern failed |
|✅     |AtomicSeekReadTest  | |
|✅     |ZeroLengthIOTest  | |
|✅     |ReadWriteRangeTest  | |
|✅     |EventAsyncIOTest  | |
|✅     |ZeroOnExtendTest  | |
|       |APCSynchRWTest  | |
|       |WriteThroughTest  | |
|       |WriteThroughSyncTest  | |
|❌     |AVChangeLogTest  | not implemented |
|✅     |IntegrityTest  | |


## SectionsCaching

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     |MaintainSectionMappingTest  | |
|❌     |DataImageCoherencyTest  | Failed getting statistics |
|❌     |ExistingUserMappingTest  | Expect sharing_violation |
|❌     |TruncateWithUserMappingTest  | 〃 |
|❌     |ExtendingWithUserMappingTest  | 〃 |
|✅     |FlushBuffersRootTest  | Failed getting statistics |


## ObjectId

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|❌     |SetObjectIDTest  | |
|❌     |GetObjectIDTest  | |
|❌     |SetUniqueObjectIDDuplicateNameTest  | |
|       |SetUniqueObjectIDNameCollisionTest  | |
|       |DeleteObjectIDTest  | |
|       |CreateOrGetObjectIDTest  | |
|       |ObjectOpenByIDTest  | |
|       |NameInformationExTest  | |
|       |SetExtendedObjectIDTest  | |
|       |SetObjectIDVolumeTest  | |
|       |GetObjectIDVolumeTest  | |
|       |EnumObjectIDTest  | |
|       |NotificationObjectIDAddedTest  | |
|       |NotificationObjectIDRemovedTest  | |
|       |NotificationObjectIDDeletedTest  | |
|       |NotificationObjectIDNotTunnelledTest  | |
|       |NotificationObjectIDTunnelledCollisionTest  | |
|       |TunnelObjectIDTest  | |


## MountPoints

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|❌     |FileGraftTest  | should fail file |
|       |FileGraftStreamTest  | |
|       |DirectoryGraftEmptyTest  | |
|       |DirectoryGraftEmptyFileTest  | |
|       |DirectoryGraftEmptyStreamTest  | |
|       |CreateDirectoryExDirectoryTest  | |
|       |CreateDirectoryExVolumeTest  | |
|       |DirectoryGraftTest  | |
|       |LocalMountPointTest  | |


## ReparsePoints

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |SetPointInvalidParamTest  | |
|       |SetPointAccessDeniedTest  | |
|       |SetPointInvalidBufferSizeTest  | |
|       |SetPointIoReparseDataInvalidTest  | |
|       |SetPointIoReparseTagInvalidTest  | |
|       |SetPointDirectoryNotEmptyTest  | |
|       |SetPointEASNotSupportedTest  | |
|       |SetPointIoReparseTagMismatchTest  | |
|       |SetPointAttributeConflictTest  | |
|       |GetPointInvalidParamTest  | |
|       |GetPointInvalidUserBufferTest  | |
|       |GetPointNotReparseTest  | |
|       |GetPointBufferSmallTest  | |
|       |DelPointInvalidParmTest  | |
|       |DelPointAccessDeniedTest  | |
|       |DelPointInvalidBufferSizeTest  | |
|       |DelPointIoReparseDataInvalidTest  | |
|       |DelPointIoReparseTagInvalidTest  | |
|       |DelPointNotReparseTest  | |
|       |DelPointIoReparseTagMismatchTest  | |
|       |DelPointAttributeConflictTest  | |
|       |FileAttributeReparsePointTest  | |
|       |OpenReparsePointTest  | |
|       |EnumReparsePointleAttributeTagInfoTest  | |
|       |QueryFullAttributesReparseTest  | |
|       |ChangeNotificationReparseTest  | |
|       |DeleteFileDirReparsePointTest  | |


## SparseFiles

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |SparseStreamTest  | |
|       |SparseStreamDirTest  | |
|       |SparseNonSparseStreamTest  | |
|       |FileInformationSparseAttrTest  | |
|       |ResetSparseAttrOverwriteTest  | |
|       |ResetSparseAttrSupersedeTest  | |
|       |SparseCompressedStreamTest  | |
|       |SparseMoveFileTest  | |
|       |SparseZeroDataTest  | |
|       |SparseZeroDataAllocTest  | |
|       |SparseUserMapZeroTest  | |
|       |SparseAllocatedRangesTest  | |
|       |SparseUserMappedSectionTest  | |


## Encryption

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |CreateEncryptedFileTest  | |
|       |CreateEncryptedDirTest  | |
|       |SuperOverEncryptedTest  | |
|       |DirectoryEncryptedNewFileTest  | |
|       |DirectoryEncryptedSuperOverTest  | |
|       |DirectoryEncryptedNewDirTest  | |
|       |EncryptDecryptFileTest  | |
|       |ReadWriteRawEncryptedTest  | |
|       |EncryptionStatusTest  | |
|       |EncryptionAttributeTest  | |
|       |EncryptionCompressionTest  | |
|       |EncryptionDecompressionTest  | |
|       |AddUseptionTest  | |
|       |RemoveUsersEncryptionTest  | |
|       |QueryUsersEncryptionTest  | |
|       |QueryRecoveryAgentsTest  | |


## Quotas

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |VolumeQuotaNoneTest  | |
|       |VolumeQuotaTrackTest  | |
|       |VolumeQuotaEnforceTest  | |
|       |VolumeQuotaUserThresholdTest  | |
|       |VolumeQuotaThresholdTest  | |
|       |VolumeQuotaUserLimitTest  | |
|       |VolumeQuotaLimitTest  | |
|       |QuerySetQueryQuotaTest  | |


## ChangeJournal

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |DeleteChangeJournalTest  | |
|       |CreateChangeJournalTest  | |
|       |ReadChangeJournalTest  | |
|       |ReadFileChangeJournalTest  | |
|       |WriteCloseRecordTest  | |
|       |QueryChangeJournalTest  | |
|       |ChangeJournalTest  | |
|       |ChangeJournalTrimTest  | |



## StreamEnhancements

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |StreamRenameTest  | |
|       |StreamDeleteTest  | |
|       |StreamQueryNamesTest  | |
|       |StreamNotifyNameTest  | |
|       |StreamNotifySizeTest  | |
|       |StreamNotifyWriteTest  | |


## DefragEnhancements

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |MoveDirTest  | |
|       |MoveViewTest  | |


## Virus

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |VirusNormalTest  | |
|       |VirusNameTest  | |
|       |VirusSizeTest  | |


## FileSystemControlVolume

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |ControlLockVolumeTest  | |
|       |ControlUnLockVolumeTest  | |
|       |ControlDismountVolumeTest  | |
|       |VolumeMountedTest  | |
|       |MountedDirtyTest  | |
|       |InvalidateVolumesTest  | |
|       |MountVerifyVolumeTest  | |
