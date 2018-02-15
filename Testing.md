
IFSTEST.EXE

Security
❌        SetDaclSecurityTest
❌        SetOwnerSecurityTest
❌        SetGroupSecurityTest
❌        SetSaclSecurityTest
❌        AuditOwnerSecurityTest
❌        DirectoryTraverseTest


OpenCreateGeneral
          FileSystemDeviceOpenTest
✅        FileFullPathCreationTest
✅        DirectoryFullPathCreationTest
✅        FileRelativePathCreationTest
✅        DirectoryRelativePathCreationTest
❌        FileOpenByIDTest
          - fails due to attributes mismatch?
❌        NonDirectoryFileOpenTest
          - Fails but STATUS expected is STATUS received?
❌        OpenVolumeTest
          - locking failure, should be exclusive
❌        CreatePagingFileTest
          - not yet supported
❌        FileNameLengthTest
          - fails at 512 out of 1024
✅        HFHTest
✅        UnicodeOnDiskTest
❌        CaseSensitiveTest
✅        PreserveCaseTest
❌        ShortFileNameTest
          - Don't handle shortnames yet.
❌        ShareAccessTest
          - do not have any share logic locking out opens
✅        AlternateStreamTest
✅        StreamShareTest


OpenCreateParameters
✅        OpenFileTest
✅        OpenFileDirTest
✅        CreateFileTest
❌        CreateFileDirTest
❌        OpenAlwaysFileTest *
❌        OpenAlwaysFileDirTest
❌        OverwriteFileTest
❌        OverwriteFileAllocTest
❌        OverwriteFileAttrTest
❌        OverwriteAlwaysAllocTest
❌        OverwriteAlwaysAttrTest
❌        SupersedeFileTest
❌        SupersedeFileAllocTest
❌        SupersedeFileAttrTest
❌        FileAllocationSizeTest
✅        ExecuteAccessTest
❌        ReadOnlyAttributeTest
❌        HiddenAttributeTest
❌        SystemAttributeTest
❌        ArchiveAttributeTest
❌        NormalAttributeTest
❌        DirectoryAttributeTest


CloseCleanupDelete
          VolumeUnlockOnCloseTest
❌        UpdateOnCloseTest
❌        UpdateOnCloseDirTest
✅        TruncateOnCloseTest
❌        DeleteOnLastCloseTest
❌        TunnelingTest


VolumeInformation
✅        VolumeInformationTest
✅        SizeInformationTest
✅        DeviceInformationTest
✅        AttributeInformationTest


FileInformation
❌        BasicInformationTest
❌        StandardInformationTest
✅        InternalInformationTest
❌        EaInformationTest
✅        NameInformationTest
❌        AllInformationTest
❌        AllocationInformationTest
❌        ZeroAllocationInformationTest
          CompressionInformationTest


onInformationTest
✅        EndOfFileInformationTest
❌        LinkInformationTest
          SimpleRenameInformationTest
❌        ConflictingRenameInformationTest
☢        AlternateNameInformationTest
        FileNetworkOpenInformationTest
        StreamInformationTest
        StreamStandardInformationTest
        HardLinkInformationTest
        TimeStampTest
EaInformation
        CreateEaInformationTest
        SetEaInformationTest
        SingleEaEntryTest
        FullEaInformationTest
        ListEaInformationTest
        IndexEaInformationTest
DirectoryInformation
        FileNameDirectoryInformationTest
        FileDirectoryInformationTest
        FullDirectoryInformationTest
        BothDirectoryInformationTest
FileLocking
        LockSharedExTest
        UnlockRangeTest
        LockOverlapTest
        LockRangeTest
        LockFailImmediateTest
        LockOverlappedTest
        UnlockAllTest
        UnlockRangeOnCloseTest
        LockKeyTest
OpLocks
        OplockBreakItoIITest
        OplockBreakIandIIOnCloseTest
        OplockIIWriteBreakingTest
        BatchOplocksTest
        BreakNotifyTest
        FilterOplockTest
        CompleteImmediatelyTest
        OplockReadBreakItoIITest
        OplockLevel1Test
        OplockSetInfoBreakTest
        LockOplockBreakTest
ChangeNotification
        NotificationDeleteTest
        NotificationCloseTest
        NotificationFilenameTest
        NotificationNonDirectoryTest
        NotificationSecurityTest
        NotificationCleanupAttribTest
DeviceControl
        DeviceIoControlTest
FileSystemControlGeneral
        GetRetrievalPointersTest
        SetCompressionTest
        GetVolumeBitmapTest
        MoveFileTest
        AllowExtendedDASDTest
ReadWrite
        ReadWriteTest
        ReadWriteCoherencyTest
        AppendDataTest
        AtomicSeekReadTest
        ZeroLengthIOTest
        ReadWriteRangeTest
        EventAsyncIOTest
        ZeroOnExtendTest
        APCSynchRWTest
        WriteThroughTest
        WriteThroughSVChangeLogTest
        IntegrityTest
SectionsCaching
        MaintainSectionMappingTest
        DataImageCoherencyTest
        ExistingUserMappingTest
        TruncateWithUserMappingTest
        ExtendingWithUserMappingTest
        FlushBuffersRootTest
ObjectId
        SetObjectIDTest
        GetObjectIDTest
        SetUniqueObjectIDDuplicateNameTest
        SetUniqueObjectIDNameCollisionTest
        DeleteObjectIDTest
        CreateOrGetObjectIDTest
        ObjectOpenByIDTest
        NameInformationExTest
        SetExtendedObjectIDTest
        SetObjectIDVolumeTest
        GetObjectIDVolumeTest
        EnumObjectIDTest
        NotificationObjectIDAddedTest
        NotificationObjectIDRemovedTest
        NotificationObjectIDDeletedTest
        NotificationObjectIDNotTunnelledTest
        NotificationObjectIDTunnelledCollisionTest
        TunnelObjectIDTest
MountPoints
        FileGraftTest
        FileGraftStreamTest
        DirectoryGraftEmptyTest
        DirectoryGraftEmptyFileTest
        Dir
        CreateDirectoryExDirectoryTest
        CreateDirectoryExVolumeTest
        DirectoryGraftTest
        LocalMountPointTest
ReparsePoints
        SetPointInvalidParamTest
        SetPointAccessDeniedTest
        SetPointInvalidBufferSizeTest
        SetPointIoReparseDataInvalidTest
        SetPointIoReparseTagInvalidTest
        SetPointDirectoryNotEmptyTest
        SetPointEASNotSupportedTest
        SetPointIoReparseTagMismatchTest
        SetPointAttributeConflictTest
        GetPointInvalidParamTest
        GetPointInvalidUserBufferTest
        GetPointNotReparseTest
        GetPointBufferSmallTest
        DelPointInvalidParmTest
        DelPointAccessDeniedTest
        DelPointInvalidBufferSizeTest
        DelPointIoReparseDataInvalidTest
        DelPointIoReparseTagInvalidTest
        DelPointNotReparseTest
        DelPointIoReparseTagMismatchTest
        DelPointAttributeConflictTest
        FileAttributeReparsePointTest
        OpenReparsePointTest
        EnumReparsePointleAttributeTagInfoTest
        QueryFullAttributesReparseTest
        ChangeNotificationReparseTest
        DeleteFileDirReparsePointTest
SparseFiles
        SparseStreamTest
        SparseStreamDirTest
        SparseNonSparseStreamTest
        FileInformationSparseAttrTest
        ResetSparseAttrOverwriteTest
        ResetSparseAttrSupersedeTest
        SparseCompressedStreamTest
        SparseMoveFileTest
        SparseZeroDataTest
        SparseZeroDataAllocTest
        SparseUserMapZeroTest
        SparseAllocatedRangesTest
        SparseUserMappedSectionTest
Encryption
        CreateEncryptedFileTest
        CreateEncryptedDirTest
        SuperOverEncryptedTest
        DirectoryEncryptedNewFileTest
        DirectoryEncryptedSuperOverTest
        DirectoryEncryptedNewDirTest
        EncryptDecryptFileTest
        ReadWriteRawEncryptedTest
        EncryptionStatusTest
        EncryptionAttributeTest
        EncryptionCompressionTest
        EncryptionDecompressionTest
        AddUseptionTest
        RemoveUsersEncryptionTest
        QueryUsersEncryptionTest
        QueryRecoveryAgentsTest
Quotas
        VolumeQuotaNoneTest
        VolumeQuotaTrackTest
        VolumeQuotaEnforceTest
        VolumeQuotaUserThresholdTest
        VolumeQuotaThresholdTest
        VolumeQuotaUserLimitTest
        VolumeQuotaLimitTest
        QuerySetQueryQuotaTest
ChangeJournal
        DeleteChangeJournalTest
        CreateChangeJournalTest
        ReadChangeJournalTest
        ReadFileChangeJournalTest
        WriteCloseRecordTest
        QueryChangeJournalTest
        ChangeJournalTest
        ChangeJournalTrimTest
StreamEnhancements
        StreamRenameTest
        StreamDeleteTest
        StreamQueryNamesTest
        StreamNotifyNameTest
        StreamNotifySizeTest
        StreamNotifyWriteTest
DefragEnhancements
        MoveDirTest
        MoveViewTest
Virus
        VirusNormalTest
        VirusNameTest
        VirusSizeTest
FileSystemControlVolume
        ControlLockVolumeTest
        Cont       ControlDismountVolumeTest
        VolumeMountedTest
        MountedDirtyTest
        InvalidateVolumesTest
        MountVerifyVolumeTest
