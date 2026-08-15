#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlinkat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/linux_premigration/guest_namespace_authority.h>


extern char* strcpy(char* dst, const char* src);

long sys_unlinkat(int fd, const char* path, int flag)
{
	int ret;
	struct vchroot_expand_args vc;
	int linux_flags;

	vc.flags = 0;
	vc.dfd = atfd(fd);
	
	if (!path)
		return -EFAULT;
	if (darling_guest_namespace_state() == DARLING_GUEST_NAMESPACE_REQUIRED) {
		if (path[0] != '/') return -ENOTSUP;
		linux_flags = atflags_bsd_to_linux(flag);
		if (linux_flags == LINUX_AT_INVALID) return -EINVAL;
		ret = darling_guest_namespace_unlink(path, linux_flags);
		return ret < 0 ? errno_linux_to_bsd(ret) : ret;
	}

	strcpy(vc.path, path);

#ifdef EUNION
	// E-UNION: NEVER delete a lower-only name from the shared template. Decide the
	// policy BEFORE expand/syscall. SKIP => the name was lower-only and is now
	// whited-out; report success without touching the template. PROCEED => the
	// target is in the upper layer; delete it, then whiteout if it also shadows a
	// template entry. (Absolute guest paths only; relative is left to the syscall.)
	if (path[0] == '/') {
		int pol = vchroot_prepare_unlink(path);
		if (pol < 0)
			return errno_linux_to_bsd(pol);
		if (pol == VCHROOT_UNLINK_SKIP)
			return 0; // hidden via whiteout; the template is untouched
	}
#endif

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	linux_flags = atflags_bsd_to_linux(flag);
	if (linux_flags == LINUX_AT_INVALID)
		return -EINVAL;

	ret = LINUX_SYSCALL(__NR_unlinkat, vc.dfd, vc.path, linux_flags);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

#ifdef EUNION
	// the upper object was removed; if the name still exists in the lower
	// template, drop a whiteout so the merged view keeps it deleted.
	if (ret == 0 && path[0] == '/')
		vchroot_post_unlink(path);
#endif

	return ret;
}
