add_library(libefi
	rdwr_efi.c
)
target_link_libraries(libefi PRIVATE libuuid zlib)