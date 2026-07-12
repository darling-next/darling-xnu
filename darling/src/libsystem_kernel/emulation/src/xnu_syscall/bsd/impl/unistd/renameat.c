#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

extern char* strcpy(char* dst, const char* src);

long sys_renameat(int oldfd, const char* oldpath, int newfd, const char* newpath)
{
	int ret;
	struct vchroot_expand_args vc, vc2;

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
	char old_guest_path[4096], new_guest_path[4096];
	int old_path_prepared = 0;
	int new_path_prepared = 0;
	int old_union = vchroot_canonical_guest_path(vc.dfd, oldpath,
		old_guest_path, sizeof(old_guest_path));
	int new_union = vchroot_canonical_guest_path(vc2.dfd, newpath,
		new_guest_path, sizeof(new_guest_path));
	if (old_union < 0)
		return errno_linux_to_bsd(old_union);
	if (new_union < 0)
		return errno_linux_to_bsd(new_union);
	if (old_union == 0) {
		int wr = vchroot_copyup_tree(old_guest_path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
	// destination side: copy up the dest's parent (so the move lands in the upper
	// layer, not the template) and whiteout a lower-only dest namesake. Also
	// clears any stale whiteout at the dest. Replaces the old pre_mkdir, which
	// only cleared a whiteout and left rename-into-template / dest-overwrite holes.
	if (new_union == 0) {
		int wr = vchroot_prepare_rename_dest(new_guest_path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
	if (old_union == 0) {
		vc.dfd = -100;
		if (vchroot_upper_guest_path(old_guest_path, vc.path, sizeof(vc.path)) < 0)
			return -ENAMETOOLONG;
		old_path_prepared = 1;
	}
	if (new_union == 0) {
		vc2.dfd = -100;
		if (vchroot_upper_guest_path(new_guest_path, vc2.path, sizeof(vc2.path)) < 0)
			return -ENAMETOOLONG;
		new_path_prepared = 1;
	}
#endif

	ret = old_path_prepared ? 0 : vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = new_path_prepared ? 0 : vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_renameat, vc.dfd, vc.path, vc2.dfd, vc2.path);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef EUNION
	if (old_union == 0) {
		int post = vchroot_post_unlink(old_guest_path);
		if (post < 0)
			return errno_linux_to_bsd(post);
	}
#endif

	return 0;
}
