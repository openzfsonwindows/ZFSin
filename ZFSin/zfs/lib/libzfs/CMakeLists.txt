add_library(libzfs
	libzfs_changelist.c
	libzfs_config.c
	libzfs_crypto.c
	libzfs_dataset.c
	libzfs_diff.c
	libzfs_fru.c
	libzfs_graph.c
	libzfs_import.c
	libzfs_iter.c
	libzfs_mount.c
	libzfs_pool.c
	libzfs_sendrecv.c
	libzfs_status.c
	libzfs_util.c
)
target_include_directories(libzfs BEFORE PRIVATE ../libspl/include)
target_link_libraries(libzfs PUBLIC libpthread zlib)