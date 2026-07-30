#include <darling/emulation/xnu_syscall/bsd/impl/unistd/mknod.h>

#include <sys/errno.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/conversion/common_at.h>

long sys_mknod(const char* path, int mode, int dev)
{
	int ret;
	struct vchroot_expand_args vc;

	vc.flags = 0;
	vc.dfd = get_perthread_wd();
	if (!path)
		return -EFAULT;

#ifdef EUNION
	char guest_path[4096];
	int union_path = vchroot_canonical_guest_create_path(
		vc.dfd, path, guest_path, sizeof(guest_path));
	if (union_path < 0)
		return errno_linux_to_bsd(union_path);
	if (union_path == 0) {
		int wr = vchroot_prepare_create(guest_path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
		ret = vchroot_mknod_create(
			guest_path, (unsigned int)mode, (unsigned int)dev);
		if (ret < 0)
			return errno_linux_to_bsd(ret);
		return 0;
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
