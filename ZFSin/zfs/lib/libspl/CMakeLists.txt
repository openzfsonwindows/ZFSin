add_library(libspl
    asm-generic/atomic.c
    crypto/edonr/edonr.c
    crypto/sha2/sha2.c
    crypto/skein/skein.c
    crypto/skein/skein_block.c
    crypto/skein/skein_iv.c
    fdatasync.c
    gethrestime.c
    gethrtime.c
    getmntany.c
    getopt.c
    getoptl.c
    list.c
    mkdirp.c
    crc32.c
    posix.c
    timestamp.c
    uio.c
    xdr.c
    xdr_array.c
    xdr_float.c
    xdr_mem.c
    zmount.c
    zone.c
)
target_include_directories(libspl BEFORE PUBLIC include)
target_link_libraries(libspl PRIVATE libpthread advapi32 shell32)