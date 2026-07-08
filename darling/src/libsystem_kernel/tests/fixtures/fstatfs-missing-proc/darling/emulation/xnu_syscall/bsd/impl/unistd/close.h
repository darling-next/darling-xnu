#include "fstatfs_missing_proc_stubs.h"

static inline long close_internal(int fd)
{
	(void)fd;
	return 0;
}
