#include <darling/emulation/other/mach/lkm.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>
#include <_libkernel_init.h>

#include <darling/emulation/linux_premigration/signal/sigexc.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/misc/ioctl.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/linux_premigration/ext/sys/linux_time.h>

#include <elfcalls.h>

extern int sys_open(const char*, int, int);
extern int close_internal(int);
extern int sys_write(int, const void*, int);
extern int sys_kill(int, int);
extern int sys_getrlimit(int, struct rlimit*);
extern int sys_dup2(int, int);
extern int sys_fcntl(int, int, int);
extern _libkernel_functions_t _libkernel_functions;

VISIBLE
struct elf_calls* _elfcalls;

// perf#30 (doc section 206): the call label lives here, ABOVE every site that needs it. MEASURED: the eager socket
// requests that the hard oracle denies come from NON-CALL sites (the guard table at libc init and the post-fork
// refresh), so those sites must be able to name THEMSELVES; with the label declared further down the file their
// report carried a stale call name instead and pointed the fix at the wrong place.
static const char* __dserver_current_call = "unknown";

static bool use_per_thread_driver_fd = false;

extern void _xtrace_postfork_child(void);

void mach_driver_init(const char** applep)
{
#ifdef VARIANT_DYLD
	if (applep != NULL)
	{
		int i;
		for (i = 0; applep[i] != NULL; i++)
		{
			if (strncmp(applep[i], "elf_calls=", 10) == 0)
			{
				uintptr_t table = (uintptr_t) __simple_atoi16(applep[i] + 10, NULL);
				_elfcalls = (struct elf_calls*) table;
			}
		}
	}
#else
	// ask for elfcalls already set up by dyld
	void* (*p2)(void);
	_libkernel_functions->dyld_func_lookup("__dyld_get_elfcalls", (void**)&p2);

	_elfcalls = p2();

	if (applep) {
		// this is not a fork; guard the main thread's RPC FD we get from mldr
		// (in the child after a fork, sys_fork already takes care of this)
		// perf#30 (doc section 206): the SITE is named, not the last call. MEASURED: the hard oracle's denial carried
		// `call=fork_wait_for_child`, which is a STICKY label from the last request this thread happened to make --
		// an eager socket request from a non-call site can only be attributed by naming the site itself.
		__dserver_current_call = "guard:init";
		guard_entry_options_t options;
		options.close = _elfcalls->dserver_close_socket;
		// perf#30 REMOVAL STEP 3b: the fd guarded here is the PROCESS socket (the only AF_UNIX endpoint left). After a
		// fork the child has none -- the loader invalidates it -- so an absent descriptor is SKIPPED, not registered as
		// -1, which would make the guard table hold an invalid entry.
		int process_socket = __dserver_process_socket();
		if (process_socket >= 0) {
			guard_table_add(process_socket, guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}
		int lifetime_pipe = __dserver_get_process_lifetime_pipe();
		if (lifetime_pipe != -1) {
			options.close = _elfcalls->dserver_close_process_lifetime_pipe;
			guard_table_add(lifetime_pipe, guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}
	}
#endif

	// mach_driver_init() gets called at several points in application's lifetime:
	// 1) When dyld loads
	// 2) When libc initializes
	// 3) After forking

	// this was previously done when the LKM was in-use.
	// now with per-thread dserver FDs, this is more complicated to do.
	// TODO: find a suitable way of doing this.
#if 0
#ifdef VARIANT_DYLD
	struct rlimit lim;
	if (sys_getrlimit(RLIMIT_NOFILE, &lim) == 0 && driver_fd != lim.rlim_cur)
	{
		// sys_getrlimit intentionally reports a limit lower by 1
		// so that our fd remains "hidden" to applications.
		// It also means rlim_cur is not above the limit
		// in the following statement.
		int d = sys_dup2(driver_fd, lim.rlim_cur);
		close_internal(driver_fd);

		driver_fd = d;
	}
#endif
#endif

	if (!applep) {
		// we're being called in the child after a fork; let xtrace know about it
		_xtrace_postfork_child();
	}
}

__attribute__((visibility("default")))
int lkm_call(int call_nr, void* arg)
{
	__simple_printf("Something called the old LKM API (nr = %d)\n", call_nr);
	__builtin_unreachable();
}

__attribute__((visibility("default")))
int lkm_call_raw(int call_nr, void* arg)
{
	__simple_printf("Something called the old LKM API (nr = %d)\n", call_nr);
	__builtin_unreachable();
}

// perf#30 (directive section 25): the ACCEPTANCE HATCH lives here, in the image that knows the call name.
// Every generated wrapper sets the name before asking for the socket, so a denied creation names the callnum
// that still needs the per-thread transport -- the migration instrument, and the reason the label in the mldr
// accessor could never answer this (it described a thread entry, not a call).
// NOT __thread: the i386 variant of this image has no __tlv_bootstrap, and a diagnostic that aborts the
// process on first use does not need per-thread precision -- the name is written immediately before the
// request that denies it.


// libc-free environment scan (the same discipline dserver-ring.c uses): this code runs before and around the
// bootstrap, where getenv is not available and an in-band instrumented path is a measured boot hazard.
static int __dserver_hatch_enabled(void) {
	static int cached = -1;
	if (cached >= 0) { return cached; }
	static const char key[] = "DARLING_DISABLE_THREAD_RPC_UDS=1";
	int fd = (int)LINUX_SYSCALL(__NR_openat, -100 /*AT_FDCWD*/, "/proc/self/environ", 0 /*O_RDONLY*/, 0);
	cached = 0;
	if (fd >= 0) {
		static char buf[8192];
		long n = LINUX_SYSCALL(__NR_read, fd, buf, sizeof(buf) - 1);
		LINUX_SYSCALL(__NR_close, fd);
		if (n > 0) {
			buf[n] = '\0';
			for (long i = 0; i + (long)(sizeof(key) - 1) <= n; ++i) {
				int match = 1;
				for (__SIZE_TYPE__ j = 0; j < sizeof(key) - 1; ++j) {
					if (buf[i + (long)j] != key[j]) { match = 0; break; }
				}
				if (match) { cached = 1; break; }
			}
		}
	}
	return cached;
}

// perf#30 INSTRUMENT: the C side of the guest Darwin syscall trace, called from the dispatcher's entry hook
// (bsd_syscall.S). Opt-in with DARLING_GUEST_SYSCALL_TRACE=1; the hatch is scanned once from /proc/self/environ
// with raw syscalls, and the output is BOUNDED, because a print per syscall at this rate is the log flood this
// project has already been burnt by.
static int __bsys_trace_enabled(void) {
	static int cached = -1;
	if (cached >= 0) { return cached; }
	static const char key[] = "DARLING_GUEST_SYSCALL_TRACE=1";
	cached = 0;
	int fd = (int)LINUX_SYSCALL(__NR_openat, -100, "/proc/self/environ", 0, 0);
	if (fd >= 0) {
		static char buf[8192];
		long n = LINUX_SYSCALL(__NR_read, fd, buf, sizeof(buf) - 1);
		LINUX_SYSCALL(__NR_close, fd);
		if (n > 0) {
			buf[n] = '\0';
			for (long i = 0; i + (long)(sizeof(key) - 1) <= n; ++i) {
				int match = 1;
				for (__SIZE_TYPE__ j = 0; j < sizeof(key) - 1; ++j) {
					if (buf[i + (long)j] != key[j]) { match = 0; break; }
				}
				if (match) { cached = 1; break; }
			}
		}
	}
	return cached;
}

static void __bsys_put_ulong(char* buf, int* at, unsigned long v) {
	char tmp[24];
	int n = 0;
	if (v == 0) { tmp[n++] = '0'; }
	while (v > 0) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
	while (n > 0) { buf[(*at)++] = tmp[--n]; }
}

// MEASURED (2026-09-27): the emitter must NOT use __simple_printf. Its output takes a `write` syscall through this
// very dispatcher, so the trace captured its own writes (21 of its first 28 lines) and the guest stopped starting.
// A RAW LINUX write is executed by the host kernel and does not re-enter the dispatcher.
static void __bsys_emit(long nr) {
	char buf[64];
	int at = 0;
	if (nr < 0) {
		const char tag[] = "[bsys bound-reached]";
		for (unsigned i = 0; i < sizeof(tag) - 1; ++i) { buf[at++] = tag[i]; }
		buf[at++] = '\n';
		LINUX_SYSCALL(__NR_write, 2, buf, at);
		return;
	}
	const char tag[] = "[bsys nr=";
	for (unsigned i = 0; i < sizeof(tag) - 1; ++i) { buf[at++] = tag[i]; }
	__bsys_put_ulong(buf, &at, (unsigned long)nr);
	const char tid_tag[] = " tid=";
	for (unsigned i = 0; i < sizeof(tid_tag) - 1; ++i) { buf[at++] = tid_tag[i]; }
	__bsys_put_ulong(buf, &at, (unsigned long)(int)LINUX_SYSCALL(__NR_gettid));
	buf[at++] = ']';
	buf[at++] = '\n';
	LINUX_SYSCALL(__NR_write, 2, buf, at);
}

VISIBLE
void __darling_bsd_syscall_trace_c(long nr, const long* args) {
	static long printed = 0;
	(void)args;
	if (!__bsys_trace_enabled()) { return; }
	// MEASURED (2026-09-27): the bound was 400 lines PER PROCESS and the workload's own bootstrap (dyld, libpthread)
	// consumes it before `main`, so the interesting calls were silently absent -- "no traced syscall after this mark"
	// was an artifact of the cap, not an observation. The cap is per process and much larger, and reaching it is an
	// EVENT that prints once: silent truncation is the defect class this whole diagnostic set exists to remove.
	if (printed >= 20000) {
		if (printed == 20000) { ++printed; __bsys_emit(-1); }
		return;
	}
	++printed;
	__bsys_emit(nr);
}

VISIBLE
void __dserver_note_call(const char* name) {
	__dserver_current_call = name;
};

VISIBLE
int mach_driver_get_fd(void) {
	// perf#30 REMOVAL STEP 3a (measured): this accessor no longer PROVIDES a per-thread RPC socket. It is the kernel
	// image's dual of the loader accessor and the same measurement closes both: a whole boot plus a 15-workload suite
	// under DARLING_DISABLE_THREAD_RPC_UDS=1 report ZERO creations and ZERO denials, so no call in that surface asks
	// for one any more. The report is therefore UNCONDITIONAL -- the hatch used to be the only path that printed
	// anything -- and it keeps naming the call, the image and the caller's offset, because that line is what NAMES the
	// next callnum to move if a decline ever happens. The token stays `rpc-socket-DENIED`: the acceptance harness counts
	// exactly that string, so a decline can never pass unnoticed. The hatch keeps the hard abort; the default returns a
	// transport failure, so a non-critical caller fails instead of killing the process.
	{
		const char* dfmt;
#ifdef VARIANT_DYLD
		dfmt = "[rpc-socket-DENIED] pid=%d tid=%d call=%s image=dyld delta=0x%lx denied=1\n";
#else
		dfmt = "[rpc-socket-DENIED] pid=%d tid=%d call=%s image=kernel delta=0x%lx denied=1\n";
#endif
		/* plain storage, not _Atomic-qualified: the __atomic_* builtins reject an _Atomic-qualified operand (measured
		 * as a compile error, not a style preference). */
		static unsigned g_get_fd_declined = 0;
		unsigned n = __atomic_fetch_add(&g_get_fd_declined, 1, __ATOMIC_RELAXED) + 1;
		if (n <= 8) {
			__simple_printf(dfmt, (int)LINUX_SYSCALL(__NR_gettid), (int)LINUX_SYSCALL(__NR_gettid),
				__dserver_current_call,
				(unsigned long)((char*)__builtin_return_address(0) - (char*)&mach_driver_get_fd));
		}
	}
	if (__dserver_hatch_enabled()) {
		__simple_abort();
	}
	return -1;
};

VISIBLE
void* elfcalls_get_pointer(void) {
	return _elfcalls;
};

VISIBLE
uint64_t mach_absolute_time(void)
{
	struct timespec ts;
	uint64_t out;
	
	clock_gettime(CLOCK_MONOTONIC, &ts);
	
	out = ts.tv_nsec;
	out += ts.tv_sec * NSEC_PER_SEC;
	
	return out;
}

VISIBLE
boolean_t voucher_mach_msg_set(mach_msg_header_t *msg)
{
	// UNIMPLEMENTED_TRAP();
	return 0;
}

VISIBLE
void voucher_mach_msg_revert(voucher_mach_msg_state_t state)
{
	// UNIMPLEMENTED_TRAP();
}

VISIBLE
voucher_mach_msg_state_t voucher_mach_msg_adopt(mach_msg_header_t *msg)
{
	// UNIMPLEMENTED_TRAP();
	return NULL;
}
