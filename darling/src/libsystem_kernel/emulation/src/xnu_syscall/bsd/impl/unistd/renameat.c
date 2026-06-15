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
	// PoC limitation: a lower-only *directory* source only copies up its top dir
	// here, not its descendants (gVisor F.3 recursion); files and empty dirs are
	// correct. Tracked in DESIGN.md.
	if (oldpath[0] == '/') {
		int wr = vchroot_prepare_write(oldpath);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
	if (newpath[0] == '/')
		vchroot_pre_mkdir(newpath);
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
