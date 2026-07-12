#include <darling/emulation/xnu_syscall/bsd/impl/xattr/removexattr.h>

#include <sys/errno.h>

extern char* strcpy(char* dst, const char* src);

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define XATTR_NOFOLLOW	1

long sys_removexattr(const char* path, const char* name, int options)
{
	int ret;

#ifdef EUNION
	// E-UNION xattr policy (mirrors setxattr):
	//  (1) marker isolation: removing a union-private marker (user.union.*) would
	//      let the guest clear a whiteout/opaque and resurrect/unhide content.
	//      Reject with EPERM.
	//  (2) expand the path (the baseline never did -- pre-EUNION bug) and copy up a
	//      lower-only target first so the remove lands on the WRITABLE upper copy
	//      and never mutates the shared read-only template.
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
		ret = LINUX_SYSCALL(__NR_lremovexattr, vc.path, name);
	else
		ret = LINUX_SYSCALL(__NR_removexattr, vc.path, name);
#else
	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lremovexattr, path, name);
	else
		ret = LINUX_SYSCALL(__NR_removexattr, path, name);
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
}
