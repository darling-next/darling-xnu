#include <darling/emulation/xnu_syscall/bsd/impl/stat/rmdir.h>

#include <sys/errno.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/other/mach/lkm.h>

#define LINUX_AT_REMOVEDIR	0x200

extern char* strcpy(char* dst, const char* src);

long sys_rmdir(const char* path)
{
	int ret;
	struct vchroot_expand_args vc;

	if (!path)
		return -EFAULT;

	vc.flags = 0;
	vc.dfd = get_perthread_wd();

	strcpy(vc.path, path);

#ifdef EUNION
	// E-UNION: a lower-only directory must be hidden with a whiteout, never
	// rmdir'd out of the shared template. SKIP => already whited-out, done.
	// PROCEED => the dir is in the upper layer; rmdir it, then whiteout if a
	// template namesake remains. (See vchroot_prepare_unlink.)
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
			return 0;
		vc.dfd = -100;
		strcpy(vc.path, guest_path);
	}
#endif

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_unlinkat, vc.dfd, vc.path, LINUX_AT_REMOVEDIR);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef EUNION
	// the upper dir was removed; if the lower template still has it, whiteout so
	// the merged view keeps it deleted instead of resurrecting the template dir.
	if (union_path == 0) {
		int post = vchroot_post_unlink(guest_path);
		if (post < 0)
			return errno_linux_to_bsd(post);
	}
#endif

	return 0;
}
