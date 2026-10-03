#include <darling/emulation/xnu_syscall/bsd/impl/unistd/mknod.h>

#include <sys/errno.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_mknod(const char* path, int mode, int dev)
{
	int ret;
	struct vchroot_expand_args vc;

	vc.flags = 0;
	vc.dfd = get_perthread_wd();
	if (!path)
		return -EFAULT;

#ifdef EUNION
	// copy up the parent dir (so the node lands in the upper layer, not the
	// shared template) and clear any whiteout at the new name.
	if (path[0] == '/') {
		int wr = vchroot_prepare_create(path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
#endif

	strcpy(vc.path, path);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	#if defined(__NR_mknod)
		ret = LINUX_SYSCALL(__NR_mknod, vc.path, mode, dev);
	#else
		ret = LINUX_SYSCALL(__NR_mknodat, LINUX_AT_FDCWD, vc.path, mode, dev);
	#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
