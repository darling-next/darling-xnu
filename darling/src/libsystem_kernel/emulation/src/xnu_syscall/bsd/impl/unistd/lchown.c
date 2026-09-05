#include <darling/emulation/xnu_syscall/bsd/impl/unistd/lchown.h>

#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchownat.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_lchown(const char* path, int uid, int gid)
{
	return sys_fchownat(get_perthread_wd(), path, uid, gid,
		BSD_AT_SYMLINK_NOFOLLOW);
}
