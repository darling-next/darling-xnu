#include <darling/emulation/xnu_syscall/bsd/impl/unistd/unlinkat.h>

#include <sys/errno.h>
#include <string.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>


long sys_unlinkat(int fd, const char* path, int flag)
{
	int ret;
	struct vchroot_expand_args vc;
	int linux_flags;

	vc.flags = 0;
	vc.dfd = atfd(fd);
	
	if (!path)
		return -EFAULT;

	strcpy(vc.path, path);

#ifdef EUNION
	// E-UNION: NEVER delete a lower-only name from the shared template. Decide the
	// policy BEFORE expand/syscall. SKIP => the name was lower-only and is now
	// whited-out; report success without touching the template. PROCEED => the
	// target is in the upper layer; delete it, then whiteout if it also shadows a
	// template entry.
	char guest_path[4096];
	int union_path = vchroot_canonical_guest_path(vc.dfd, path,
		guest_path, sizeof(guest_path));
	if (union_path < 0)
		return errno_linux_to_bsd(union_path);
	if (union_path == 0) {
		int pol = vchroot_prepare_unlink(guest_path);
		if (pol < 0)
			return errno_linux_to_bsd(pol);
		if (pol == VCHROOT_UNLINK_SKIP)
			return 0; // hidden via whiteout; the template is untouched
		vc.dfd = -100;
		strcpy(vc.path, guest_path);
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
	if (ret == 0 && union_path == 0) {
		int post = vchroot_post_unlink(guest_path);
		if (post < 0)
			return errno_linux_to_bsd(post);
	}
#endif

	return ret;
}
