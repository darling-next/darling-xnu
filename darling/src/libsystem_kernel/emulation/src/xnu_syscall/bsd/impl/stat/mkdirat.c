#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdirat.h>

#include <sys/errno.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/other/mach/lkm.h>

extern char* strcpy(char* dst, const char* src);

long sys_mkdirat(int fd, const char* path, unsigned int mode)
{
	int ret;
	struct vchroot_expand_args vc;

	if (!path)
		return -EFAULT;

	vc.flags = 0;
	vc.dfd = atfd(fd);

#ifdef EUNION
	// copy up the parent dir (so the new dir lands in the upper layer, not the
	// shared template) and clear any whiteout at the new name (mkdir over a
	// previously-deleted name resurrects it).
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

	ret = LINUX_SYSCALL(__NR_mkdirat, vc.dfd, vc.path, mode);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return 0;
}
