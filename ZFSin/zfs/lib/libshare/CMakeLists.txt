add_library(libshare
	libshare.c
    nfs.c
    smb.c
)
target_link_libraries(libshare PUBLIC libspl)