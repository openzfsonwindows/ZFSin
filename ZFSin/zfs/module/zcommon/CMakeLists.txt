wdk_add_library(zcommonkern
	zfs_comutil.c
	zfs_deleg.c
	zfs_fletcher.c
	zfs_namecheck.c
	zfs_prop.c
	zpool_prop.c
	zprop_common.c
)

target_link_libraries(zcommonkern PRIVATE splkern)
