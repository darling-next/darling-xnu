#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchown.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

long sys_fchown(int fd, int uid, int gid)
{
	int ret;
	int wfd = fd;
#ifdef EUNION
	wfd = vchroot_fd_for_meta_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
#endif

#ifdef __NR_fchown32
	ret = LINUX_SYSCALL3(__NR_fchown32, wfd, uid, gid);
#else
	ret = LINUX_SYSCALL3(__NR_fchown, wfd, uid, gid);
#endif
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
