#include <darling/emulation/xnu_syscall/bsd/impl/unistd/symlinkat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_symlinkat(const char* path, int fd, const char* link)
{
	int ret;
	struct vchroot_expand_args vc;

	vc.flags = 0;
	vc.dfd = atfd(fd);

#ifdef EUNION
	char guest_path[4096];
	int union_path = vchroot_canonical_guest_create_path(
		vc.dfd, link, guest_path, sizeof(guest_path));
	if (union_path < 0)
		return errno_linux_to_bsd(union_path);
	if (union_path == 0) {
		int wr = vchroot_prepare_create(guest_path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
		ret = vchroot_symlink_create(path, guest_path, 0);
		if (ret < 0)
			return errno_linux_to_bsd(ret);
		return 0;
	}
#endif

	strcpy(vc.path, link);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_symlinkat, path, vc.dfd, vc.path);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
