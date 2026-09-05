#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchownat.h>

#include <sys/errno.h>
#include <string.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/conversion/stat/common.h>

long sys_fchownat(int fd, const char* path, int uid, int gid, int flag)
{
	if (!path)
		return -EFAULT;
	if (flag & ~BSD_AT_SYMLINK_NOFOLLOW)
		return -EINVAL;

	struct vchroot_expand_args vc;
	size_t length = strnlen(path, sizeof(vc.path));
	if (length == sizeof(vc.path))
		return -ENAMETOOLONG;
	if (!length)
		return -ENOENT;
	vc.flags = (flag & BSD_AT_SYMLINK_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	// vchroot resolves dirfds through procfs, which does not itself enforce
	// EBADF/ENOTDIR (and would accept a regular-file fd followed by "..").
	int ret;
	if (path[0] != '/' && vc.dfd != LINUX_AT_FDCWD)
	{
		struct linux_stat st;
#ifdef __NR_fstat64
		ret = LINUX_SYSCALL(__NR_fstat64, vc.dfd, &st);
#else
		ret = LINUX_SYSCALL(__NR_fstat, vc.dfd, &st);
#endif
		if (ret < 0)
			return errno_linux_to_bsd(ret);
		if ((st.st_mode & 0170000) != 0040000)
			return -ENOTDIR;
	}

	memcpy(vc.path, path, length + 1);
#ifdef EUNION
	ret = vchroot_expand_for_meta_write(&vc);
#else
	ret = vchroot_expand(&vc);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
#ifndef EUNION
	if (path[length - 1] == '/')
	{
		size_t resolved_length = strlen(vc.path);
		if (resolved_length + 1 >= sizeof(vc.path))
			return -ENAMETOOLONG;
		vc.path[resolved_length] = '/';
		vc.path[resolved_length + 1] = '\0';
	}
#endif

	// The resolver has already followed the guest target when requested.
	// Never let Linux follow a copied guest-absolute symlink a second time.
	ret = LINUX_SYSCALL(__NR_fchownat, vc.dfd, vc.path, uid, gid,
		LINUX_AT_SYMLINK_NOFOLLOW);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
