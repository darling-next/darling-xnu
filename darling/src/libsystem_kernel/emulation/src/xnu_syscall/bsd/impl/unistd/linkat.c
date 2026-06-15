#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/link.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

extern char* strcpy(char* dst, const char* src);

long sys_linkat(int fd, const char* path, int fdlink, const char* link, int flag)
{
	int ret;
	struct vchroot_expand_args vc, vc2;
	int linux_flags;

	if (!path || !link)
		return -EFAULT;

	vc.flags = (flag & BSD_AT_SYMLINK_FOLLOW) ? VCHROOT_FOLLOW : 0;
	vc.dfd = atfd(fd);

	strcpy(vc.path, path);

	vc2.flags = 0;
	vc2.dfd = atfd(fdlink);

	strcpy(vc2.path, link);

#ifdef EUNION
	// hardlink: the source must live in the writable upper layer (you cannot link
	// a file out of the read-only template into it), and the new name must clear
	// any whiteout. Note: copy-up breaks link identity (st_nlink resets) -- same
	// behaviour as gVisor; documented in DESIGN.md.
	if (path[0] == '/') {
		int wr = vchroot_prepare_write(path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
	}
	if (link[0] == '/')
		vchroot_pre_mkdir(link);
#endif

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	linux_flags = atflags_bsd_to_linux(flag);
	if (linux_flags == LINUX_AT_INVALID)
		return -EINVAL;

	ret = LINUX_SYSCALL(__NR_linkat, vc.dfd, vc.path, vc2.dfd, vc2.path, linux_flags);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
