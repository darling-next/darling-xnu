#include <darling/emulation/xnu_syscall/bsd/impl/unistd/ftruncate.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

long sys_ftruncate(int fd, long long length)
{
	int ret;

#ifdef EUNION
	// E-UNION: ftruncate mutates file CONTENT by descriptor. If `fd` was opened on
	// a lower-only object, truncating via the fd would shrink the SHARED template.
	// Copy it up and operate on a fresh WRITABLE fd targeting the upper copy
	// (ftruncate needs O_RDWR -- the meta-write helper's O_RDONLY fd would EINVAL).
	// Returns the original fd if unmanaged.
	int wfd = vchroot_fd_for_content_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
#ifdef __NR_ftruncate64
	ret = LINUX_SYSCALL(__NR_ftruncate64, wfd, LL_ARG(length));
#else
	ret = LINUX_SYSCALL(__NR_ftruncate, wfd, LL_ARG(length));
#endif
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
#else
#ifdef __NR_ftruncate64
	ret = LINUX_SYSCALL(__NR_ftruncate64, fd, LL_ARG(length));
#else
	ret = LINUX_SYSCALL(__NR_ftruncate, fd, LL_ARG(length));
#endif
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
