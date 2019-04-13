um_add_executable(zstreamdump
	zstreamdump.c
)
target_link_libraries(zstreamdump PRIVATE
	libnvpair
	libuutil
	libuuid
	libzfs
	libzfs_core
	libzpool
)
install(TARGETS zstreamdump RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES $<TARGET_PDB_FILE:zstreamdump>
	DESTINATION "${CMAKE_INSTALL_BINDIR}"
	OPTIONAL
)