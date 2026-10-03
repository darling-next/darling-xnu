#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>

#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#ifndef O_NOFOLLOW
#	define O_NOFOLLOW 0x0100
#endif
#ifndef O_CLOEXEC
#	define O_CLOEXEC 0x1000000
#endif
#ifndef O_DIRECTORY
#	define O_DIRECTORY 0x100000
#endif

extern int strcmp(const char *s1, const char *s2);

/* Diagnostic probe with ATTRIBUTION and with NO syscall of its own.
 *
 * The identity must be free AND portable: this dylib is built for x86_64 AND i386, so `%rsp` is rejected by the
 * 32-bit pass, and an earlier version called gettid (__NR_gettid == 186) inside the probe on a hot path -- the
 * run being measured got SHORTER, because a probe that adds an emulated syscall to the code it measures is not
 * a neutral observer. The address of a local buffer costs nothing and is distinct per thread and per frame.
 *
 * rax uses LINUX numbering: write is 1. See scripts/guest-probe.h -- a wrong number here is silent. */
static void __open_probe(const char *tag, int digit) {
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



/* WHICH PATH IS BEING OPENED. MEASURED: one process opens files in a loop (40+ opens on one sp) and never reaches the
 * workload's first print, and the stage marks name only who called open, never what for -- so the loop could not be
 * attributed to a loader search, a retry, or a wrong root. The tag is a literal; the path bytes follow it in the SAME
 * single write, so the probe still adds no syscall per call and cannot write twice. */
static void __open_path_probe(const char *path) {
	char buf[64];
	int n = 0, i;
	for (const char *c = "[open-path "; *c; ++c) buf[n++] = *c;
	if (path != 0) {
		for (i = 0; i < 44 && path[i] != '\0'; ++i) buf[n++] = path[i];
	} else {
		buf[n++] = '0';
	}
	buf[n++] = ']'; buf[n++] = '\n';
	{
		long rax = 1, rdi = 2, rsi = (long)buf, rdx = n;
		__asm__ volatile("syscall" : "+a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx) : : "rcx", "r11", "memory");
	}
}

long sys_open(const char* filename, int flags, unsigned int mode)
{
	__open_probe("[open-entry", -1);
	CANCELATION_POINT();
	__open_probe("[open-postcancel", -1);
	int wd = get_perthread_wd();
	__open_probe("[open-postwd", -1);
	__open_path_probe(filename);
	return sys_openat_nocancel(wd, filename, flags, mode);
}

long sys_open_nocancel(const char* filename, int flags, unsigned int mode)
{
	__open_probe("[open-nocancel-entry", -1);
	int wd = get_perthread_wd();
	__open_probe("[open-nocancel-postwd", -1);
	return sys_openat_nocancel(wd, filename, flags, mode);
}
