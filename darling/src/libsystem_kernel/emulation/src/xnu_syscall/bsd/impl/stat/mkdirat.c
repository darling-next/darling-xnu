#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkdirat.h>

#include <sys/errno.h>
#include <string.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/other/mach/lkm.h>

long sys_mkdirat(int fd, const char* path, unsigned int mode)
{
	int ret;
	struct vchroot_expand_args vc;

	if (!path)
		return -EFAULT;

	vc.flags = 0;
	vc.dfd = atfd(fd);

#ifdef EUNION
	// copy up the parent dir (so the new dir lands in the upper layer, not the
	// shared template) and clear any whiteout at the new name (mkdir over a
	// previously-deleted name resurrects it).
	int prepared_create_path = 0;
	char guest_path[4096];
	int union_path = vchroot_canonical_guest_create_path(vc.dfd, path,
		guest_path, sizeof(guest_path));
	if (union_path < 0)
		return errno_linux_to_bsd(union_path);
	if (union_path == 0) {
		int wr = vchroot_prepare_create_path(guest_path, vc.path, sizeof(vc.path));
		if (wr < 0)
			return errno_linux_to_bsd(wr);
		prepared_create_path = wr > 0;
	}
#endif

#ifdef EUNION
	if (!prepared_create_path) {
#endif
		strcpy(vc.path, path);

		ret = vchroot_expand(&vc);
		if (ret < 0)
			return errno_linux_to_bsd(ret);
#ifdef EUNION
	}
#endif

	ret = LINUX_SYSCALL(__NR_mkdirat, vc.dfd, vc.path, mode);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef EUNION
	// If the new dir shadows a LOWER directory (delete-recreate of a populated
	// dir), mark it opaque so the stale lower children are not re-merged. Only
	// meaningful for an absolute guest path; best-effort (a failed opaque-set does
	// not undo the successful mkdir, but the dir would then leak lower content --
	// so surface the error to the caller).
	if (union_path == 0) {
		int op = vchroot_post_mkdir(guest_path);
		if (op < 0)
			return errno_linux_to_bsd(op);
	}
#endif

	return 0;
}
