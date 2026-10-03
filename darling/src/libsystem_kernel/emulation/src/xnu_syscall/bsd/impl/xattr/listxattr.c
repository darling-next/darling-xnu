#include <darling/emulation/xnu_syscall/bsd/impl/xattr/listxattr.h>

#include <sys/errno.h>
#include <string.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

#define XATTR_NOFOLLOW	1

long sys_listxattr(const char* path, char* namebuf, unsigned long size, int options)
{
	int ret;
	struct vchroot_expand_args vc;

	vc.flags = (options & XATTR_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();

	if (!path)
		return -EFAULT;

	strcpy(vc.path, path);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

#ifdef EUNION
	// E-UNION: the baseline issued the host syscall against the UN-expanded `path`
	// (it expanded then ignored the result -- a latent bug). Under the union we
	// must list the resolved object, so use vc.path.
	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_llistxattr, vc.path, namebuf, size);
	else
		ret = LINUX_SYSCALL(__NR_listxattr, vc.path, namebuf, size);

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	// Marker isolation: the union's overlay-private markers (user.union.*) must
	// not leak into the guest's attribute listing. The kernel returns a
	// NUL-separated list of names totalling `ret` bytes; compact it in place,
	// dropping every name in the reserved namespace and shrinking the byte count.
	// (When size==0 the kernel returns the buffer size needed and writes no names;
	// there is nothing to filter, and we leave that probe value unchanged -- a
	// mild over-estimate by the markers' length, which the spec permits.)
	if (size != 0 && ret > 0)
	{
		int in = 0, out = 0;
		while (in < ret)
		{
			const char* nm = namebuf + in;
			int nlen = 0;
			while (in + nlen < ret && nm[nlen] != '\0')
				nlen++;
			int entry = nlen + 1; // include the NUL terminator
			if (!vchroot_xattr_is_marker(nm))
			{
				if (out != in)
					memmove(namebuf + out, nm, entry);
				out += entry;
			}
			in += entry;
		}
		ret = out;
	}
#else
	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_llistxattr, path, namebuf, size);
	else
		ret = LINUX_SYSCALL(__NR_listxattr, path, namebuf, size);

	if (ret < 0)
		return errno_linux_to_bsd(ret);
#endif

	return ret;
}
