#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchown.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

long sys_fchown(int fd, int uid, int gid)
{
	// E-UNION HAZARD (dar-test-infra-sp5.8.4.4.8): this stub is SAFE only because
	// it is disabled (returns 0, no mutation). If it is ever un-stubbed, it becomes
	// an immediate template-corruption path: fchown() on an fd that still points at
	// a shared LOWER-template file mutates ownership in the template for ALL
	// prefixes. Before re-enabling, the fd MUST be copied up first --
	// vchroot_prepare_write_fd(fd) -- and the chown applied to the returned UPPER
	// fd, exactly as the fd-metadata syscalls (e.g. fchmod) already do under EUNION.
#if 0
	int ret;

#ifdef __NR_fchown32
	ret = LINUX_SYSCALL3(__NR_fchown32, fd, uid, gid);
#else
	ret = LINUX_SYSCALL3(__NR_fchown, fd, uid, gid);
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
#else
	return 0;
#endif
}
