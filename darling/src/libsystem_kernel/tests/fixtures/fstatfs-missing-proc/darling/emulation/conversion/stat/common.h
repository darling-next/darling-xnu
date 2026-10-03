#include "fstatfs_missing_proc_stubs.h"

static inline void statfs_linux_to_bsd64(struct linux_statfs64* linux_buf, struct bsd_statfs64* bsd_buf)
{
	(void)linux_buf;
	bsd_buf->converted_from_linux = 1;
}
