#ifndef LIBSPL_STATVFS_H_INCLUDED
#define LIBSPL_STATVFS_H_INCLUDED

#include <mntent.h>
int statfs(const char* path, struct statfs* buf);

#endif