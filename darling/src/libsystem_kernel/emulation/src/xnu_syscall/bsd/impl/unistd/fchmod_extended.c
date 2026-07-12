#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchmod_extended.h>

#include <sys/types.h>
#include <sys/kauth.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

long sys_fchmod_extended(int fd, int uid, int gid, int mode, void* xsec)
{
	int ret;

	// apparently, these are supposed to go through successfully
	if (uid == KAUTH_UID_NONE || gid == KAUTH_GID_NONE || mode == -1) {
		return 0;
	}

#ifdef EUNION
	// E-UNION: copy up a lower-only object and apply chmod+chown to a fresh fd on
	// the upper copy, never the shared template. Both ops target the same fd.
	int wfd = vchroot_fd_for_meta_write(fd);
	if (wfd < 0)
		return errno_linux_to_bsd(wfd);
	ret = LINUX_SYSCALL2(__NR_fchmod, wfd, mode);
	if (ret >= 0)
		ret = LINUX_SYSCALL(__NR_fchown, wfd, uid, gid);
	if (wfd != fd)
		LINUX_SYSCALL(__NR_close, wfd);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	return ret;
#else
	ret = LINUX_SYSCALL2(__NR_fchmod, fd, mode);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_fchown, fd, uid, gid);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
#endif
}
