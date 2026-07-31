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

static bool use_per_thread_driver_fd = false;

extern void _xtrace_postfork_child(void);
extern int __darling_vchroot(int dfd);

#define VCHROOT_FD_APPLE_PREFIX "vchroot_fd="

static int retained_vchroot_fd_from_apple(const char** applep)
{
	if (!applep)
		return -1;

	for (int i = 0; applep[i] != NULL; i++) {
		const char* entry = applep[i];
		if (strncmp(entry, VCHROOT_FD_APPLE_PREFIX,
			sizeof(VCHROOT_FD_APPLE_PREFIX) - 1) != 0)
			continue;

		const char* cursor = entry + sizeof(VCHROOT_FD_APPLE_PREFIX) - 1;
		unsigned int value = 0;
		if (*cursor == '\0')
			return -1;
		for (; *cursor != '\0'; cursor++) {
			if (*cursor < '0' || *cursor > '9')
				return -1;
			if (value > (0x7fffffffU - (unsigned int)(*cursor - '0')) / 10U)
				return -1;
			value = value * 10U + (unsigned int)(*cursor - '0');
		}
		return (int)value;
	}
	return -1;
}

static void anchor_retained_vchroot(const char** applep)
{
	int descriptor = retained_vchroot_fd_from_apple(applep);
	if (descriptor < 0 || __darling_vchroot(descriptor) != 0) {
		__simple_printf(
			"invalid retained vchroot directory capability at image initialization\n");
		__simple_abort();
	}

#ifndef VARIANT_DYLD
	// dyld and libsystem_kernel have separate E-UNION state. Keep the original
	// descriptor alive until both images have duplicated and validated it; the
	// non-dyld initializer is the final consumer.
	close_internal(descriptor);
#endif
}

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
		guard_entry_options_t options;
		options.close = _elfcalls->dserver_close_socket;
		guard_table_add(__dserver_per_thread_socket(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		int lifetime_pipe = __dserver_get_process_lifetime_pipe();
		if (lifetime_pipe != -1) {
			options.close = _elfcalls->dserver_close_process_lifetime_pipe;
			guard_table_add(lifetime_pipe, guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}
	}
#endif

	if (applep)
		anchor_retained_vchroot(applep);

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

VISIBLE
int mach_driver_get_fd(void) {
	return __dserver_per_thread_socket();
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
