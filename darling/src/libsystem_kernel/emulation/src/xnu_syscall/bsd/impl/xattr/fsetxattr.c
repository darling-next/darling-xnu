#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fsetxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

long sys_fsetxattr(int fd, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	int ret;

	if (pos != 0)
		return -ERANGE;

#ifdef EUNION
	// E-UNION: copy up a lower-only object and set the xattr on a fresh fd on the
	// upper copy, never the shared template. (Marker-namespace isolation for the
	// path-based setxattr/removexattr is handled separately under .5.)
	int wfd = vchroot_fd_for_meta_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
	ret = LINUX_SYSCALL(__NR_fsetxattr, wfd, name, value, size);
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
#else
	ret = LINUX_SYSCALL(__NR_fsetxattr, fd, name, value, size);
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
}
