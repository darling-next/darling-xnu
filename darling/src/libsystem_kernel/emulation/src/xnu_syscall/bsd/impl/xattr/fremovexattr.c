#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fremovexattr.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

long sys_fremovexattr(int fd, const char* name, int options)
{
	int ret;

#ifdef EUNION
	// E-UNION: copy up a lower-only object and remove the xattr from a fresh fd on
	// the upper copy, never the shared template.
	int wfd = vchroot_fd_for_meta_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
	ret = LINUX_SYSCALL(__NR_fremovexattr, wfd, name);
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
#else
	ret = LINUX_SYSCALL(__NR_fremovexattr, fd, name);
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
}
