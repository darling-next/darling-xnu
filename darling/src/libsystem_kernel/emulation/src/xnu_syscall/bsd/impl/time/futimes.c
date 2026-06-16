#include <darling/emulation/xnu_syscall/bsd/impl/time/futimes.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>


long sys_futimes(int fd, struct bsd_timeval* tv)
{
	int ret;
	struct linux_timeval ltv[2];

	ltv[0].tv_sec = tv[0].tv_sec;
	ltv[0].tv_usec = tv[0].tv_usec;
	ltv[1].tv_sec = tv[1].tv_sec;
	ltv[1].tv_usec = tv[1].tv_usec;

#ifdef EUNION
	// E-UNION: copy up a lower-only object and stamp times on a fresh fd targeting
	// the upper copy, never the shared template. (utimensat with a NULL path acts
	// on the fd's object.)
	int wfd = vchroot_fd_for_meta_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
	ret = LINUX_SYSCALL(__NR_utimensat, wfd, NULL, ltv, 0);
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
#else
	ret = LINUX_SYSCALL(__NR_utimensat, fd, NULL, ltv, 0);
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
