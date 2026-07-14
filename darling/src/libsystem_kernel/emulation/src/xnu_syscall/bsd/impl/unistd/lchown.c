#include <darling/emulation/xnu_syscall/bsd/impl/unistd/lchown.h>

#include <sys/errno.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_lchown(const char* path, int uid, int gid)
{
	if (!path)
		return -EFAULT;

	// E-UNION HAZARD (dar-test-infra-sp5.8.4.4.8): this stub is SAFE only because
	// it is disabled (returns ENOTSUP, no mutation). If it is ever un-stubbed, it
	// becomes
	// an immediate template-corruption path: the body below vchroot_expand()s the
	// guest path and lchowns it -- but for a lower-only target that expanded path is
	// the shared LOWER template, so the chown mutates ownership for ALL prefixes.
	// Before re-enabling, copy the target up first -- vchroot_prepare_write(path)
	// (path-based copy-up). Because lchown operates on the symlink itself (no
	// follow), the copy-up must materialize the LINK in the upper layer, not its
	// target.
#if 0
	int ret;
	struct vchroot_expand_args vc;

	vc.flags = 0;
	vc.dfd = get_perthread_wd();
	
	strcpy(vc.path, path);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef __NR_chown32
	ret = LINUX_SYSCALL(__NR_lchown32, vc.path, uid, gid);
#else
	ret = LINUX_SYSCALL(__NR_lchown, vc.path, uid, gid);
#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
#else
	return -ENOTSUP;
#endif
}
