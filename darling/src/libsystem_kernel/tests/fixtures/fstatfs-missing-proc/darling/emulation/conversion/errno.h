#include "fstatfs_missing_proc_stubs.h"

static inline long errno_linux_to_bsd(long ret)
{
	return ret;
}
