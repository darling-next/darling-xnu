#ifndef LINUX_GETATTRLISTBULK_H
#define LINUX_GETATTRLISTBULK_H

#include <darling/emulation/conversion/xattr/getattrlist.h>

long sys_getattrlistbulk(int fd, struct xnu_attrlist* alist, void* attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options);

#endif // LINUX_GETATTRLISTBULK_H
