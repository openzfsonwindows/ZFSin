
# IFSTEST.EXE

## Security

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|❌     | SetDaclSecurityTest    | Security not yet implemented |
|❌     | SetOwnerSecurityTest   | |
|❌     | SetGroupSecurityTest   | |
|❌     | SetSaclSecurityTest    | |
|❌     | AuditOwnerSecurityTest | |
|❌     | DirectoryTraverseTest  | |


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
|✅     | FileNameLengthTest  | fails at 512 out of 1024 |
|✅     | HFHTest  | |
|✅     | UnicodeOnDiskTest  | |
|✅     | CaseSensitiveTest  | |
|✅     | PreserveCaseTest  | |
|❌     | ShortFileNameTest  | Don't handle shortnames yet |
|❌     | ShareAccessTest  | do not have any share logic locking out opens |
|✅     | AlternateStreamTest  | |
|✅     | StreamShareTest  | |


## OpenCreateParameters

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|✅     | OpenFileTest  | |
|✅     | OpenFileDirTest  | |
|✅     | CreateFileTest  | |
|❌     | CreateFileDirTest  | |
|❌     | OpenAlwaysFileTest  | | *
|❌     | OpenAlwaysFileDirTest  | |
|❌     | OverwriteFileTest  | |
|❌     | OverwriteFileAllocTest  | |
|❌     | OverwriteFileAttrTest  | |
|❌     | OverwriteAlwaysAllocTest  | |
|❌     | OverwriteAlwaysAttrTest  | |
|❌     | SupersedeFileTest  | |



|❌     | SupersedeFileAllocTest  | |
|❌     | SupersedeFileAttrTest  | |
|❌     | FileAllocationSizeTest  | |
|✅     | ExecuteAccessTest  | |
|❌     | ReadOnlyAttributeTest  | |
|❌     | HiddenAttributeTest  | |
|❌     | SystemAttributeTest  | |
|❌     | ArchiveAttributeTest  | |
|❌     | NormalAttributeTest  | |
|❌     | DirectoryAttributeTest  | |


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
|❌     | BasicInformationTest  | |
|❌     | StandardInformationTest  | |
|✅     | InternalInformationTest  | |
|❌     | EaInformationTest  | |
|✅     | NameInformationTest  | |
|❌     | AllInformationTest  | |
|❌     | AllocationInformationTest  | |
|❌     | ZeroAllocationInformationTest  | |
|       | CompressionInformationTest  | |
|       | DispositionInformationTest  | |
|✅     | EndOfFileInformationTest  | |
|❌     | LinkInformationTest  | |
|       | SimpleRenameInformationTest  | |
|❌     | ConflictingRenameInformationTest  | |
|☢     | AlternateNameInformationTest  | |
|       | FileNetworkOpenInformationTest  | |
|       | StreamInformationTest  | |
|       | StreamStandardInformationTest  | |
|       | HardLinkInformationTest  | |
|       | TimeStampTest  | |


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
|       |FileNameDirectoryInformationTest  | |
|       |FileDirectoryInformationTest  | |
|       |FullDirectoryInformationTest  | |
|       |BothDirectoryInformationTest  | |


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
|       |NotificationDeleteTest  | |
|       |NotificationCloseTest  | |
|       |NotificationFilenameTest  | |
|       |NotificationNonDirectoryTest  | |
|       |NotificationSecurityTest  | |
|       |NotificationCleanupAttribTest  | |


## DeviceControl

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |DeviceIoControlTest  | |


## FileSystemControlGeneral

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |GetRetrievalPointersTest  | |
|       |SetCompressionTest  | |
|       |GetVolumeBitmapTest  | |
|       |MoveFileTest  | |
|       |AllowExtendedDASDTest  | |


## ReadWrite

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |ReadWriteTest  | |
|       |ReadWriteCoherencyTest  | |
|       |AppendDataTest  | |
|       |AtomicSeekReadTest  | |
|       |ZeroLengthIOTest  | |
|       |ReadWriteRangeTest  | |
|       |EventAsyncIOTest  | |
|       |ZeroOnExtendTest  | |
|       |APCSynchRWTest  | |
|       |WriteThroughTest  | |
|       |WriteThroughSVChangeLogTest  | |
|       |IntegrityTest  | |


## SectionsCaching

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |MaintainSectionMappingTest  | |
|       |DataImageCoherencyTest  | |
|       |ExistingUserMappingTest  | |
|       |TruncateWithUserMappingTest  | |
|       |ExtendingWithUserMappingTest  | |
|       |FlushBuffersRootTest  | |


## ObjectId

| Sts| Test name        | Comments            |
| :---- |:--------------| :-------------------|
|       |SetObjectIDTest  | |
|       |GetObjectIDTest  | |
|       |SetUniqueObjectIDDuplicateNameTest  | |
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
|       |FileGraftTest  | |
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
