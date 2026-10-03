#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>

#include <sys/fcntl.h>
#include <string.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc-supplement.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

#ifndef O_NOFOLLOW
#	define O_NOFOLLOW 0x0100
#endif
#ifndef O_CLOEXEC
#	define O_CLOEXEC 0x1000000
#endif
#ifndef O_DIRECTORY
#	define O_DIRECTORY 0x100000
#endif

long sys_openat(int fd, const char* filename, int flags, unsigned int mode)
{
	CANCELATION_POINT();
	return sys_openat_nocancel(fd, filename, flags, mode);
}


/* Diagnostic probe with ATTRIBUTION and with NO syscall of its own.
 *
 * The identity must be free AND portable: this dylib is built for x86_64 AND i386, so `%rsp` is rejected by the
 * 32-bit pass, and an earlier version called gettid (__NR_gettid == 186) inside the probe on a hot path -- the
 * run being measured got SHORTER, because a probe that adds an emulated syscall to the code it measures is not
 * a neutral observer. The address of a local buffer costs nothing and is distinct per thread and per frame.
 *
 * rax uses LINUX numbering: write is 1. See scripts/guest-probe.h -- a wrong number here is silent. */
static void __at_probe(const char *tag, int digit) {
	char buf[64];
	int n = 0;
	/* PER-THREAD identity: the TCB self-pointer. A per-FRAME value (the address of a local buffer, an earlier
	 * version) cannot correlate probes across a call chain -- sys_open and sys_openat_nocancel have different
	 * frames -- so "does this guest reach the syscall layer" was unanswerable by identity. No syscall is added
	 * (a probe that adds one is not a neutral observer) and no TLS runtime is required. */
	unsigned long id = 0;
#if defined(__x86_64__)
	__asm__ volatile("movq %%fs:0, %0" : "=r"(id));
#elif defined(__i386__)
	__asm__ volatile("movl %%gs:0, %0" : "=r"(id));
#else
	id = (unsigned long)(void *)&n;
#endif
	for (const char *c = tag; *c && n < 40; ++c) buf[n++] = *c;
	if (digit >= 0) { buf[n++] = (char)('0' + digit % 10); }
	buf[n++] = ' '; buf[n++] = 's'; buf[n++] = 'p'; buf[n++] = '=';
	{
		static const char hex[] = "0123456789abcdef";
		char tmp[16];
		int k = 0, i;
		unsigned long v = id & 0xfffff;
		if (v == 0) tmp[k++] = '0';
		while (v > 0 && k < 16) { tmp[k++] = hex[v & 0xf]; v >>= 4; }
		for (i = 0; i < k && n < 60; ++i) buf[n++] = tmp[k - 1 - i];
	}
	buf[n++] = ']'; buf[n++] = '\n';
	{
		long rax = 1, rdi = 2, rsi = (long)buf, rdx = n;
		__asm__ volatile("syscall" : "+a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx) : : "rcx", "r11", "memory");
	}
}


long sys_openat_nocancel(int fd, const char* filename, int flags, unsigned int mode)
{
	int ret, linux_flags;
	__at_probe("[openat-entry", -1);
	if (!filename)
		return -EFAULT;

	linux_flags = oflags_bsd_to_linux(flags);

	if (sizeof(void*) == 4)
	{
		linux_flags |= LINUX_O_LARGEFILE;
	}

	// XNU /dev/random behaves like Linux /dev/urandom
	if (strcmp(filename, "/dev/random") == 0)
		filename = "/dev/urandom";
	// Expected by launchd and CF
	else if (strcmp(filename, "/dev/autofs_nowait") == 0)
		filename = "/dev/null";
	else if (strcmp(filename, "/dev/console") == 0) {
		// redirect console output to darlingserver
		// perf#30 (directive section 16): the descriptor-bearing early call goes to the process MANAGEMENT
		// PLANE for its semantics and to the process COURIER for the descriptor it returns, with the token in
		// reply_payload[1]. -1 from the plane means "not published / not completed", and only then does the
		// datagram run: a published call is never retried.
		int err;
		int planeStatusCopy = -2;
		__at_probe("[console-rpc-begin", -1);
		{
			uint64_t reply0 = 0, reply1 = 0;
			int planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_CONSOLE_OPEN,
				0, 0, 0, 0, &reply0, &reply1);
			planeStatusCopy = planeStatus;
			/* NAME THE EXACT ANSWER (dar-4cp9). MEASURED defect in this instrument: the branch below reported only
			 * `planeStatus % 10`, so a boot failure on /dev/console could not be told -1 (nothing published, the
			 * datagram fallback is expected) from a real server answer such as -2, -3 or -16 -- and those need
			 * opposite fixes. One raw line, with the full status and both reply words, makes the path readable. */
			__simple_fprintf(2, "[console-path] plane-status=%d reply0=%d reply1=%d\n",
				(int)planeStatus, (int)(int32_t)(uint32_t)reply0, (int)(int32_t)(uint32_t)reply1);
			if (planeStatus != -1) {
				if (planeStatus == 0 && reply1 != 0) {
					int resolved = __dserver_fd_courier_receive(reply1);
					__at_probe("[console-plane-fd", resolved >= 0 ? resolved % 10 : 9);
					if (resolved >= 0) {
						ret = resolved;
						return ret;
					}
				}
				// The plane's completion status IS the call's return (the same convention the other plane
				// routes use): 0 is success, negative is the server's real answer. It is NOT the internal
				// failure the old datagram wrapper reported when it had no socket -- that distinction is the
				// entire point of moving this call, because openat.c answers any negative internal error with
				// __simple_abort() inside open().
				__at_probe("[console-plane-status", planeStatus < 0 ? 9 : planeStatus % 10);
				if (planeStatus < 0) {
					return errno_linux_to_bsd(-planeStatus);
				}
				return (int)(int32_t)(uint32_t)reply0;
			}
		}
		/* NAME THE EXACT STATUS AND THE PATH (dar-4cp9). MEASURED defect in this instrument: the plane branch
		 * reported only `planeStatus % 10`, so a boot failure on /dev/console could not be told -1 (nothing
		 * published, datagram fallback expected) from -16 or -22 (the server's own answer), and the two need
		 * opposite fixes. One raw line with the full value, the deciding branch, and the datagram outcome makes
		 * the console path readable on its own. */
		err = dserver_rpc_console_open(&ret);
		if (err < 0) {
			__at_probe("[console-rpc-internal-", -err % 10);
			__simple_printf("dserver_rpc_console_open failed internally: %d", err);
			__simple_abort();
		}
		if (err > 0) {
			__at_probe("[console-rpc-fail-", err % 10);
			ret = errno_linux_to_bsd(-err);
		} else {
			__at_probe("[console-rpc-ok-fd", ret % 10);
		}
		return ret;
	}

	struct vchroot_expand_args vc;
	int use_upper_path = 0;

#ifdef EUNION
	// E-UNION: if this open writes/creates/truncates, materialize the target in
	// the writable upper layer BEFORE expand so the real syscall never mutates the
	// shared read-only template. Handles BOTH absolute paths and dirfd-relative
	// paths (openat into a lower-only dir): prepare_write_at resolves the dirfd to
	// a guest path and joins the relative target. (Read-only opens are left alone.)
	int union_path = 1;
	char guest_path[4096];
	char upper_path[4096];
	int mutating = ((flags & 0x3) == BSD_O_WRONLY || (flags & 0x3) == BSD_O_RDWR ||
		(flags & BSD_O_CREAT) || (flags & BSD_O_TRUNC));
	if (mutating || filename[0] != '/') {
	union_path = (flags & BSD_O_CREAT)
		? vchroot_canonical_guest_create_path(atfd(fd), filename,
			guest_path, sizeof(guest_path))
		: vchroot_canonical_guest_path(atfd(fd), filename,
		guest_path, sizeof(guest_path));
		if (union_path < 0)
			return errno_linux_to_bsd(union_path);
	}
	if (union_path == 0 && mutating) {
		int wr = vchroot_prepare_write(guest_path);
		if (wr < 0)
			return errno_linux_to_bsd(wr);
		if (flags & BSD_O_CREAT) {
			wr = vchroot_prepare_create_path(guest_path, upper_path, sizeof(upper_path));
			if (wr < 0)
				return errno_linux_to_bsd(wr);
			if (wr > 0) {
				strcpy(vc.path, upper_path);
				vc.dfd = LINUX_AT_FDCWD;
				use_upper_path = 1;
			}
		}
	}
#endif

	vc.flags = (flags & BSD_O_SYMLINK || flags & BSD_O_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	if (!use_upper_path) {
#ifdef EUNION
		if (union_path == 0) {
			strcpy(vc.path, guest_path);
			vc.dfd = LINUX_AT_FDCWD;
		} else
#endif
			strcpy(vc.path, filename);
		ret = vchroot_expand(&vc);
	} else {
		ret = 0;
	}
	if (ret < 0) {
		return errno_linux_to_bsd(ret);
	}

	// when we're given O_SYMLINK, `oflags_bsd_to_linux` translates it into
	// O_NOFOLLOW and O_PATH
	// this is the only way to open the symlink itself on Linux
	// unfortunately, this presents additional challenges
	// only a select few Linux syscalls support O_PATH descriptors, which means
	// that for other syscalls, we either have to check for this and use an
	// `l` variant (e.g. `llistxattr` instead of `listxatrr`) or we're screwed

	ret = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path, linux_flags, mode);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
