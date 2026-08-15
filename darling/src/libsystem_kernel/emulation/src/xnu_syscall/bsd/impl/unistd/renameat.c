#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/linux_premigration/guest_namespace_authority.h>

extern char* strcpy(char* dst, const char* src);

long sys_renameat(int oldfd, const char* oldpath, int newfd, const char* newpath)
{
	int ret;
	struct vchroot_expand_args vc, vc2;
	if (!oldpath || !newpath) return -EFAULT;
	if (darling_guest_namespace_state() == DARLING_GUEST_NAMESPACE_REQUIRED) {
		if (oldpath[0] != '/' || newpath[0] != '/') return -ENOTSUP;
		ret = darling_guest_namespace_rename(oldpath, newpath);
		return ret < 0 ? errno_linux_to_bsd(ret) : ret;
	}

	vc.flags = 0;
	vc.dfd = atfd(oldfd);
	
	strcpy(vc.path, oldpath);

	vc2.flags = 0;
	vc2.dfd = atfd(newfd);

	strcpy(vc2.path, newpath);

#ifdef EUNION
	// rename across the union: the source must be in the writable upper layer
	// (rename cannot move out of the read-only template), and the destination
	// name must clear any whiteout. After a successful rename the source name is
	// gone from upper -- if the template still has it, whiteout the origin so it
	// does not resurrect from the lower layer.
	// A lower-only DIRECTORY source must be deep-copied (node + ALL descendants):
	// once the host moves the upper dir and we whiteout the origin, the lazy
	// lower-merge no longer applies, so any descendant left only in the template
	// would vanish (gVisor copy_up.go F.3). vchroot_copyup_tree handles files
	// (single copy), symlinks, and directories (recursive) uniformly.
	if (oldpath[0] == '/') {
		int wr = vchroot_copyup_tree(oldpath);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
	// destination side: copy up the dest's parent (so the move lands in the upper
	// layer, not the template) and whiteout a lower-only dest namesake. Also
	// clears any stale whiteout at the dest. Replaces the old pre_mkdir, which
	// only cleared a whiteout and left rename-into-template / dest-overwrite holes.
	if (newpath[0] == '/') {
		int wr = vchroot_prepare_rename_dest(newpath);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
#endif

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_renameat, vc.dfd, vc.path, vc2.dfd, vc2.path);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef EUNION
	if (oldpath[0] == '/')
		vchroot_post_unlink(oldpath);
#endif

	return 0;
}
