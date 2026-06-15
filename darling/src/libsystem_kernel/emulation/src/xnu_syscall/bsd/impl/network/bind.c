#include <darling/emulation/xnu_syscall/bsd/impl/network/bind.h>

#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strlen(const char* src);
extern char* strcpy(char* dest, const char* src);
extern char *strncpy(char *dest, const char *src, __SIZE_TYPE__ n);

// Must be included after strncpy
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

long sys_bind(int fd, const void* name, int socklen)
{
	int ret;
	struct sockaddr_fixup* fixed;

	if (socklen > 512)
		return -EINVAL;

#ifdef EUNION
	// E-UNION: binding an AF_UNIX socket CREATES a filesystem object. Its parent
	// directory must live in the writable upper layer, or the bind lands in (or
	// fails against) the read-only template -- e.g. launchd binding
	// /var/run/shellspawn.sock, whose /var/run exists only in the template until
	// copied up. Materialize the parent before the path is expanded+bound.
	{
		const struct sockaddr* sa = (const struct sockaddr*) name;
		// AF_UNIX == 1 on both BSD and Linux family numbering used here
		if (sa && socklen > 2 && sa->sa_family == 1)
		{
			const char* p = ((const struct sockaddr_un*) name)->sun_path;
			if (p[0] == '/')
			{
				// copy-up the PARENT dir of the socket path
				char parent[4096];
				int n = (int) strlen(p);
				if (n > 0 && n < (int) sizeof(parent))
				{
					strcpy(parent, p);
					char* slash = parent;
					for (char* c = parent; *c; ++c)
						if (*c == '/') slash = c;
					if (slash != parent) { *slash = '\0'; vchroot_prepare_write(parent); }
				}
			}
		}
	}
#endif

	fixed = __builtin_alloca(sockaddr_fixup_size_from_bsd(name, socklen));
	ret = socklen = sockaddr_fixup_from_bsd(fixed, name, socklen);
	if (ret < 0)
		return ret;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_BIND, ((long[6]) { fd, fixed, socklen }));
#else
	ret = LINUX_SYSCALL(__NR_bind, fd, fixed, socklen);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
