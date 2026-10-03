#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_register.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/machdep/impl/tls.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>
#include <darling/emulation/common/simple.h>

#include <darlingserver/rpc.h>
#include <stdlib.h>

// perf#30 DIAGNOSIS: lock-free, libc-free marks for the create path. MEASURED: the guest's `[bsc wrap post]` (a
// __simple_printf, i.e. a Darwin `write` through the dispatcher) did not appear for the SECOND create although the
// loader's own marker showed its host `pthread_create` returning rc=0 -- so either the fault is between the loader's
// return and that print, or the print's own syscall path is what dies. RAW LINUX writes take the dispatcher out of
// the picture and separate the two.
static int __bsc_mark_enabled(void) {
	static int cached = -1;
	if (cached < 0) { const char* v = getenv("DARLING_GUEST_CREATE_TRACE"); cached = (v != NULL && v[0] == '1') ? 1 : 0; }
	return cached;
}

static void __bsc_mark_ulong(char* buf, int* at, unsigned long v) {
	char tmp[24]; int n = 0;
	if (v == 0) { tmp[n++] = '0'; }
	while (v != 0 && n < (int)sizeof(tmp)) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
	while (n > 0) { buf[(*at)++] = tmp[--n]; }
}

static void __bsc_mark(const char* tag, unsigned long a, unsigned long b) {
	if (!__bsc_mark_enabled()) { return; }
	char buf[96]; int at = 0;
	for (const char* q = tag; *q != '\0' && at < (int)sizeof(buf) - 32; ++q) { buf[at++] = *q; }
	__bsc_mark_ulong(buf, &at, a);
	buf[at++] = ' '; buf[at++] = 'b'; buf[at++] = '=';
	__bsc_mark_ulong(buf, &at, b);
	buf[at++] = '\n';
	LINUX_SYSCALL(__NR_write, 2, buf, at);
}



extern void *memset(void *s, int c, size_t n);

#define PTHREAD_START_CUSTOM    0x01000000
#define PTHREAD_START_SETSCHED  0x02000000
#define PTHREAD_START_DETACHED  0x04000000
#define PTHREAD_START_POLICY_BITSHIFT 16
#define PTHREAD_START_POLICY_MASK 0xff
#define PTHREAD_START_IMPORTANCE_MASK 0xffff

#define STACK_GUARD_SIZE 4096

static bool _uses_threads = false;

// http://www.tldp.org/FAQ/Threads-FAQ/clone.c

// perf#30 REMOVAL STEP 3c: there is no per-thread RPC fd, so there is nothing for a thread to guard or unguard -- the
// guard pair, the fd it remembered, and the callbacks entries that carried it are gone. The process socket and the
// lifetime pipe are guarded by the kernel image directly.
static const struct darling_thread_create_callbacks callbacks = {
	.thread_self_trap = &thread_self_trap_impl,
	.thread_set_tsd_base = &sys_thread_set_tsd_base,
};

long sys_bsdthread_create(void* thread_start, void* arg,
		void* stack, void* pthread, uint32_t flags)
{
#ifndef VARIANT_DYLD // dyld doesn't create threads
	int ret;
	unsigned long stacksize = 0;

	_uses_threads = true;

#ifndef BSDTHREAD_WRAP_LINUX_PTHREAD
	if (!(flags & PTHREAD_START_CUSTOM))
	{
		// perf#30 DIAGNOSIS: the minimal repro (`threadnoop 2`) dies inside the SECOND pthread_create, before
		// the new thread reaches ANY RPC, so the two client-side statements that can be responsible are named:
		// the guest stack allocation (an EMULATED mmap/mprotect, i.e. requests to the server) and the raw clone
		// itself. The marks are in the PARENT only (the child jumps away in assembly), so a missing `[bsc post-clone]`
		// says the fault is in the child's prologue -- whose first act is `call _thread_self_trap`.
		__simple_printf("[bsc %s alloc-pre]\n", uses_threads() ? "later" : "first");
		// We have to allocate stack ourselves
		pthread = stack = thread_stack_allocate(stacksize);
		__simple_printf("[bsc alloc-post stack=%p]\n", stack);
	}

	__simple_printf("[bsc pre-clone stack=%p]\n", stack);
	ret = darling_thread_create((void**) stack, pthread_entry_point_wrapper, thread_start,
			arg, stacksize, flags);
	__simple_printf("[bsc post-clone ret=%d pthread=%p]\n", ret, pthread);
#else
	// perf#30 DIAGNOSIS: THIS is the branch this build compiles (`-DBSDTHREAD_WRAP_LINUX_PTHREAD`, measured in
	// build.ninja), so the marks above are compiled out and this call is where the guest's second pthread_create
	// enters the LOADER. MEASURED need: `threadnoop 2` dies before the new thread reaches any RPC, and the loader's
	// create is the only code between the caller and that first `thread_self_trap`. The mark is printed before the
	// call: if it appears and the process still dies, the statement is inside the loader.
	__bsc_mark("[bsc pre-loader a=", (unsigned long)(uintptr_t)stack, (unsigned long)(uintptr_t)pthread);
	void* rv = __darling_thread_create(((uintptr_t)stack), pthread_obj_size,
			pthread_entry_point_wrapper, thread_start, arg, (uintptr_t) stack, flags,
			&callbacks, pthread);
	__bsc_mark("[bsc post-loader rv=", (unsigned long)(uintptr_t)rv, (unsigned long)0);
	__simple_printf("[bsc wrap post rv=%p]\n", rv);
	return rv;
#endif

	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return pthread;
#else
	return -ENOSYS;
#endif
}

void* thread_stack_allocate(unsigned long stacksize)
{
	unsigned long allocsize;
	void* stack;

	// The pthread object is placed above stack area
	allocsize = stacksize + pthread_obj_size + STACK_GUARD_SIZE;
	allocsize = (allocsize + 4095) & ~4095; // round up to page size

	stack = (void**) sys_mmap(NULL, allocsize, PROT_READ | PROT_WRITE,
			MAP_ANON | MAP_PRIVATE, -1, 0);

	// Protect the stack guard
	sys_mprotect(stack, STACK_GUARD_SIZE, PROT_NONE);
	
	if (((intptr_t)stack) < 0 && ((intptr_t)stack) >= -4095)
		return NULL;

	return (void*) (((uintptr_t)stack) + stacksize + STACK_GUARD_SIZE);
}

#if 0
int darling_thread_create(void** stack, void* entry_point, uintptr_t arg3,
		uintptr_t arg4, uintptr_t arg5, uintptr_t arg6)
{
	int ret;

#if defined(__x86_64__)
	// Store these arguments to pthread_entry point on the stack
	stack[-1] = entry_point;
	stack[-2] = arg3;
	stack[-3] = arg4;
	stack[-4] = arg5;
	stack[-5] = arg6;

	__asm__ __volatile__ (
			"syscall\n" // invoke sys_clone
			"testl %0, %0\n" // if in parent thread, jump away
			"jne 1f\n"
			"subq $40, %%rsp\n" // protect what we have stored on stack
			"call _thread_self_trap\n" // get thread_self Mach port
			"addq $40, %%rsp\n"
			"movl %%eax, %%esi\n" // thread_self is 2nd arg to pthread_entry_point
			"movq %%rsp, %%rdi\n" // pthread_self as 1st arg
			"movq -16(%%rsp), %%rdx\n" // thread_start as 3rd arg
			"movq -32(%%rsp), %%r8\n" // stack_size as 5th arg
			"movq -24(%%rsp), %%rcx\n" // thread arg as 4th arg
			"movq -40(%%rsp), %%r9\n" // flags as 6th arg
			"movq -8(%%rsp), %%rbx\n"
			"jmp *%%rbx\n"
			"1:\n"
			: "=a"(ret)
			: "0" (__NR_clone),
			"D"(LINUX_CLONE_THREAD | LINUX_CLONE_VM | LINUX_CLONE_SIGHAND 
	            | LINUX_CLONE_FILES | LINUX_CLONE_FS | LINUX_CLONE_SYSVSEM),
			"S"(stack));
#elif defined(__i386__)
#	warning Missing clone call assembly!
#else
#	warning Missing clone call assembly!
#endif
	return ret;
}
#endif

bool uses_threads(void)
{
	return _uses_threads;
}
