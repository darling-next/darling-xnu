#include <darling/emulation/xnu_syscall/bsd/impl/xattr/setxattr.h>

#include <sys/errno.h>

extern char* strcpy(char* dst, const char* src);

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define XATTR_NOFOLLOW	1

long sys_setxattr(const char* path, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	int ret;

	if (pos != 0)
		return -ERANGE;

#ifdef EUNION
	// E-UNION xattr policy:
	//  (1) marker isolation: the guest must not forge a union-private marker
	//      (user.union.*) -- doing so could fabricate a whiteout/opaque and
	//      resurrect a deleted name or unhide a lower subtree. Reject with EPERM.
	//  (2) the baseline path was never expanded (a pre-EUNION bug: the raw guest
	//      path was handed to the host syscall). Expand it through vchroot, AND
	//      copy up a lower-only target first so the setxattr lands on the WRITABLE
	//      upper copy and never mutates the shared read-only template.
	if (vchroot_xattr_is_marker(name))
		return -EPERM;

	int wr = vchroot_prepare_write(path);
	if (wr < 0)
		return errno_linux_to_bsd(wr);

	struct vchroot_expand_args vc;
	vc.flags = (options & XATTR_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();
	strcpy(vc.path, path);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lsetxattr, vc.path, name, value, size);
	else
		ret = LINUX_SYSCALL(__NR_setxattr, vc.path, name, value, size);
#else
	if (options & XATTR_NOFOLLOW)
	{
		ret = LINUX_SYSCALL(__NR_lsetxattr, path, name, value, size);
	}
	else
	{
		ret = LINUX_SYSCALL(__NR_setxattr, path, name, value, size);
	}
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
}
