#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchmod.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

long sys_fchmod(int fd, int mode)
{
	int ret;

#ifdef EUNION
	// E-UNION: if `fd` was opened on a lower-only object, mutating its metadata
	// via the fd would hit the SHARED template. Copy it up and operate on a fresh
	// fd targeting the upper copy. Returns the original fd if unmanaged.
	int wfd = vchroot_fd_for_meta_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
	ret = LINUX_SYSCALL2(__NR_fchmod, wfd, mode);
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
#else
	ret = LINUX_SYSCALL2(__NR_fchmod, fd, mode);
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
