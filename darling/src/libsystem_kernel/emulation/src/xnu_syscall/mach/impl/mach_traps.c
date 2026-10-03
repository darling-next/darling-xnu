#define ioctl __real_ioctl
#include <mach/mach_traps.h>
#include <mach/vm_statistics.h>
#include <mach/kern_return.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <mach/mach_init.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/linux_premigration/ext/mremap.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/signal/sigaction.h>
#include <darling/emulation/conversion/duct_errno.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc-supplement.h>

#include <darling/emulation/xnu_syscall/mach/impl/cached_self_ports.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>
#include <darling/emulation/linux_premigration/resources/dserver-rpc-defs.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

#define UNIMPLEMENTED_TRAP() { char msg[] = "Called unimplemented Mach trap: "; write(2, msg, sizeof(msg)-1); write(2, __FUNCTION__, sizeof(__FUNCTION__)-1); write(2, "\n", 1); }

// perf #7 (dar-dar6x4-perf-5dq.14): the task self port is immutable for a process's
// lifetime, yet the profile (perf #9) showed task_self_trap = ~13% of ALL RPCs in a
// fork/exec build (~6x per process). Cache it after the first real trap; the reset
// hook below is called from mach_init_doit() (which runs at process init AND in the
// atfork-child path) so a forked child re-traps its own new self port. See
// cached_self_ports.h for the fork-safety + macOS-contract reasoning (host_self_trap
// is deliberately NOT cached -- its result is caller-deallocated).
static cached_self_port_t __task_self_port_cache = { CACHED_MACH_PORT_NULL };

// Exposed for mach_init_doit() (libsyscall, same dylib) to reset on init/fork.
void __darling_reset_cached_self_ports(void) {
	cached_self_port_reset(&__task_self_port_cache);
}

mach_port_name_t mach_reply_port_impl(void)
{
	unsigned int port_name;
	// perf #18 P3: mach_reply_port is the UNCACHED high-frequency op (every Mach RPC round-trip
	// needs a reply port), so unlike task_self_trap it actually exercises the ring's latency win.
	// Only a negative pre-publication miss permits UDS fallback. A published failure
	// must return MACH_PORT_NULL without minting another port over UDS.
	int ring_code = __dserver_ring_mach_reply_port(&port_name);
	if (ring_code >= 0) {
		return ring_code == 0 ? port_name : MACH_PORT_NULL;
	}
	if (dserver_rpc_mach_reply_port(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

// The calling thread's LINUX tid, which is what the plane's THREAD_SELF_BOOTSTRAP wants (its
// request_payload[0]); the guest's BSD tid is not the same number. MEASURED MISTAKE, KEPT AS EVIDENCE: the
// first version of this helper used raw syscall number 186 (the host's __NR_gettid) and the guest answered
// "Unimplemented syscall (186)", then died of SIGILL -- in a Darling guest the syscall numbers are the
// GUEST's, so a hard-coded host number is not a shortcut but a fault. LINUX_SYSCALL(__NR_gettid) goes
// through the emulation's own numbering, exactly as the loader's probes do.
static unsigned thread_self_trap_caller_tid(void) {
	return (unsigned)LINUX_SYSCALL(__NR_gettid);
}

mach_port_name_t thread_self_trap_impl(void)
{
	unsigned int port_name;
	// Uncached, per-thread port. Retry only if the ring did not publish.
	int ring_code = __dserver_ring_thread_self_trap(&port_name);
	if (ring_code >= 0) {
		return ring_code == 0 ? port_name : MACH_PORT_NULL;
	}
	// NO LANE YET IS NOT A DEAD END (perf#30 / dar-4cp9). MEASURED: [dring-uds-reason ... callnum=35
	// name=generated reason=NO_LANE_ENTRY lane_slot=0 lane_gen=0 lane_state=0] immediately followed by
	// [rpc-socket-DENIED ... call=thread_self_trap image=kernel] and the guest abort -- a thread asking for its
	// own port before its lane has been attached had no transport at all, because the per-thread socket is gone.
	// The management PLANE answers exactly this question, and it is the route the loader already uses for its own
	// bootstrap (op THREAD_SELF_BOOTSTRAP: register the thread, return its port from reply_payload[0]); the
	// architecture comes from the same source every other RPC uses, so the plane sees what the RPC would have.
	// Only a pre-publish miss falls through to the ordinary RPC below, which keeps its own no-transport meaning.
	{
		uint64_t planeReply0 = 0, planeReply1 = 0;
		extern int __dserver_plane_request_ex(uint32_t op, uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3,
			uint64_t* outReply0, uint64_t* outReply1);
		int planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_THREAD_SELF_BOOTSTRAP,
			(uint64_t)(unsigned)thread_self_trap_caller_tid(),
			(uint64_t)(dserver_rpc_hooks_get_architecture() & 0xffu), 0, 0,
			&planeReply0, &planeReply1);
		if (planeStatus != -1) {
			return (mach_port_name_t)(planeReply0 & 0xffffffffu);
		}
	}
	if (dserver_rpc_thread_self_trap(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

mach_port_name_t host_self_trap_impl(void)
{
	unsigned int port_name;
	// A published ring failure must not mint a second send right over UDS.
	int ring_code = __dserver_ring_host_self_trap(&port_name);
	if (ring_code >= 0) {
		return ring_code == 0 ? port_name : MACH_PORT_NULL;
	}
	if (dserver_rpc_host_self_trap(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

mach_msg_return_t mach_msg_trap_impl(
				mach_msg_header_t *msg,
				mach_msg_option_t option,
				mach_msg_size_t send_size,
				mach_msg_size_t rcv_size,
				mach_port_name_t rcv_name,
				mach_msg_timeout_t timeout,
				mach_port_name_t notify)
{
	return mach_msg_overwrite_trap_impl(msg,
			option, send_size, rcv_size,
			rcv_name, timeout, notify,
			msg, 0);
}

// perf#30 DIAGNOSIS helpers: LINUX-numbered raw syscalls, because the mach_msg trap runs during bootstrap
// (before libc is usable) and `getenv` there is a measured boot hazard -- the same reason dserver-ring.c scans
// /proc/self/environ instead of calling getenv. Numbers are the guest's LINUX numbering: openat=257, read=0,
// close=3.
#if defined(__x86_64__)
static long __diag_sys4(long n, long a, long b, long c, long d) {
	long r;
	__asm__ volatile("movq %4, %%r10\n\tsyscall"
		: "=a"(r)
		: "a"(n), "D"(a), "S"(b), "d"(c), "rm"(d)
		: "rcx", "r11", "r10", "memory");
	return r;
}
#else
// The i386 variant of this image has no %r10 and a different syscall ABI; the probe is off there (a negative
// descriptor makes __diag_env_is1 report "not set"), which keeps this diagnostic off the 32-bit build entirely.
static long __diag_sys4(long n, long a, long b, long c, long d) {
	(void)n; (void)a; (void)b; (void)c; (void)d;
	return -1;
}
#endif

static int __diag_env_is1(const char* key) {
	static char buf[8192];
	long klen = 0;
	while (key[klen]) { ++klen; }
	long fd = __diag_sys4(257 /*openat*/, -100 /*AT_FDCWD*/, (long)"/proc/self/environ", 0 /*O_RDONLY*/, 0);
	if (fd < 0) { return 0; }
	long n = __diag_sys4(0 /*read*/, fd, (long)buf, (long)(sizeof(buf) - 1), 0);
	__diag_sys4(3 /*close*/, fd, 0, 0, 0);
	if (n <= 0) { return 0; }
	buf[n] = '\0';
	for (long i = 0; i + klen + 1 < n; ++i) {
		int ok = 1;
		for (long j = 0; j < klen; ++j) {
			if (buf[i + j] != key[j]) { ok = 0; break; }
		}
		if (ok && buf[i + klen] == '=' && buf[i + klen + 1] == '1') { return 1; }
	}
	return 0;
}

// perf#30 DIAGNOSIS helper: LINUX-numbered raw gettid (the guest's syscall numbering), so a probe can carry the
// same thread identity the server's ledger prints without including a header this file does not have.
static int __diag_tid(void) {
#ifdef __x86_64__
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(186L) : "rcx", "r11", "memory");
	return (int)ret;
#else
	return 0;
#endif
}

mach_msg_return_t mach_msg_overwrite_trap_impl(
				mach_msg_header_t *msg,
				mach_msg_option_t option,
				mach_msg_size_t send_size,
				mach_msg_size_t rcv_size,
				mach_port_name_t rcv_name,
				mach_msg_timeout_t timeout,
				mach_port_name_t notify,
				mach_msg_header_t *rcv_msg,
				mach_msg_size_t rcv_limit)
{
	int code;

	// perf#30 DIAGNOSIS: the mach_msg round-trip is the one path whose completion is invisible from both the
	// server ledger (it logs RECV/reply, which say SEND) and the workload's marks (a stall inside the guest after
	// a successful reply looks exactly like a stall before publication). Capped per process so the hot path
	// cannot flood a log; the msgh_id names the MIG routine, and entry-without-exit names the parked call.
	static int msgProbe = -1, msgProbeCount = 0;
	int probeOn = 0;
	if (msgProbe < 0) { msgProbe = __diag_env_is1("DARLING_GUEST_MACHMSG_PROBE"); }
	if (msgProbe && msgProbeCount < 400) {
		probeOn = 1;
		++msgProbeCount;
		unsigned pid_ = msg ? (unsigned)((mach_msg_header_t*)msg)->msgh_id : 0u;
		__simple_printf("[machmsg-enter n=%d id=%u option=%u send=%u rcv=%u tid=%d]\n",
			msgProbeCount, pid_, (unsigned)option, (unsigned)send_size, (unsigned)rcv_size,
			(int)__diag_tid());
	}
	// perf#26 RING-MACH-MSG: route the approved subset onto this thread's Ring lane. The helper returns
	// 0 only for a valid ring round-trip (code = the mach_msg_return_t); nonzero means a safe
	// PRE-PUBLISH miss or an explicit server PRE-DISPATCH decline, and the unchanged UDS path below
	// runs -- the operation executes exactly once either way. After a successful publish the helper
	// never falls back, so a Ring timeout cannot duplicate the operation.
	{
		int ring_code = KERN_FAILURE;
		if (__dserver_ring_mach_msg_overwrite(msg, option, send_size, rcv_size, rcv_name, timeout, notify, rcv_msg, &ring_code) == 0) {
			if (probeOn) { __simple_printf("[machmsg-exit n=%d how=ring code=%d tid=%d]\n", msgProbeCount, (int)ring_code, (int)__diag_tid()); }
			return (mach_msg_return_t)ring_code;
		}
	}

	// perf#27 #5: this op did NOT ride the Ring (no lane, or a pre-publish miss / pre-dispatch decline), so
	// record it as UDS traffic for THIS process. The formal UDS-zero gate counts these lines per process.
	__dserver_ring_note_uds_machmsg();

retry:
	code = dserver_rpc_mach_msg_overwrite(msg, option, send_size, rcv_size, rcv_name, timeout, notify, rcv_msg);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			// when the RPC call returns EINTR, it means we didn't manage to send the RPC message to the server;
			// when the RPC receive operation receives EINTR, it retries the call, meaning we should never see EINTR from an RPC receive.
			// therefore, if we wanted to both send and receive a message, this means the send (which is performed first) was interrupted.
			//
			// we also need to check if the caller wants to know about interrupts. if they want send interrupts, we tell them.
			// if they want receive interrupts, we tell them. otherwise, we retry the call.
			if ((option & MACH_SEND_MSG) != 0 && (option & MACH_SEND_INTERRUPT) != 0) {
				if (probeOn) { __simple_printf("[machmsg-exit n=%d how=send-intr tid=%d]\n", msgProbeCount, (int)__diag_tid()); }
				return MACH_SEND_INTERRUPTED;
			} else if ((option & MACH_RCV_MSG) != 0 && (option & MACH_RCV_INTERRUPT) != 0) {
				if (probeOn) { __simple_printf("[machmsg-exit n=%d how=rcv-intr tid=%d]\n", msgProbeCount, (int)__diag_tid()); }
				return MACH_RCV_INTERRUPTED;
			} else {
				goto retry;
			}
		}
		__simple_printf("mach_msg_overwrite failed (internally): %d\n", code);
		__simple_abort();
	}

	if (probeOn) { __simple_printf("[machmsg-exit n=%d how=rcp code=%d tid=%d]\n", msgProbeCount, (int)code, (int)__diag_tid()); }
	return code;
}


// perf#30 (doc section 244): WHO CALLS THE SEMAPHORE FAMILY, AND WITH WHICH NAME. MEASURED need: the server trace showed a
// `semaphore_signal` arriving with `signal_name = 0` (reply code 15, an error) while the matching waiter sat on name 2307
// -- so the signal and the wait never met and the waiter timed out for 30 seconds at a time. The server side cannot say
// who sent it, because only the guest knows its own call stack, and the semaphore family is rare enough to afford a line
// of tracing (unlike the mach_msg hot path, which is why that one uses the in-memory ring). Read the hatch ONCE, print at
// most one line per (operation, name) pair so a repeating call site cannot flood the log, and never change the call: the
// address is the caller's return address in the guest binary, to be symbolized afterwards.
static void sem_trap_site(const char* op, unsigned int a, unsigned int b) {
	static int enabled = -1;
	if (enabled < 0) {
		const char* t = getenv("DARLING_SEM_SITE_TRACE");
		enabled = (t && t[0] == '1') ? 1 : 0;
	}
	if (!enabled) {
		return;
	}
	static struct { const char* op; unsigned int a; unsigned int b; } seen[32];
	static int seenCount = 0;
	for (int i = 0; i < seenCount; ++i) {
		if (seen[i].op == op && seen[i].a == a && seen[i].b == b) {
			return;
		}
	}
	if (seenCount < 32) {
		seen[seenCount].op = op; seen[seenCount].a = a; seen[seenCount].b = b; seenCount++;
	}
	// The RAW addresses still go out, because they are the ground truth; the SYMBOLS are added because resolving a
	// raw address by hand needs the image's load base, which is not in the log -- and the question this instrument
	// exists for ("which guest caller waits 30 seconds on a semaphore during pthread_create") was answerable only
	// after that resolution. dladdr answers it in the guest, where the images are mapped.
	void* ra[4] = {
		__builtin_return_address(0),
		__builtin_return_address(1),
		__builtin_return_address(2),
		__builtin_return_address(3),
	};
	const char* sym[4] = { "<no-symbol>", "<no-symbol>", "<no-symbol>", "<no-symbol>" };
	for (int i = 0; i < 4; ++i) {
		Dl_info info;
		if (ra[i] && dladdr(ra[i], &info) && info.dli_sname) {
			sym[i] = info.dli_sname;
		}
	}
	// Four frames, not two: the first two are always the trap and its syscall dispatcher
	// (`semaphore_timedwait_trap_impl`, `_darling_mach_syscall`), so the GUEST caller this instrument was built to
	// name is the third or fourth frame. Frame pointers are not guaranteed in every image here, so the raw addresses
	// travel next to the names and a garbage frame is visible as one.
	// perf#30 (doc section 251): WHICH THREAD. MEASURED need: a 30-second semantic wait and the workload's stalled
	// `pthread_create` are impossible to relate without a per-thread identity, and the log had none. The TCB self
	// pointer is the per-thread identity this project already uses for probes: one register read, no syscall, and it
	// is stable for the life of the thread.
	unsigned long long tcb = 0;
#if defined(__x86_64__)
	__asm__ __volatile__("movq %%fs:0, %0" : "=r"(tcb));
#endif
	__simple_printf("SEM-SITE tcb=0x%llx op=%s a=0x%x b=0x%x ra=0x%llx sym0=%s ra2=0x%llx sym1=%s ra3=0x%llx sym2=%s ra4=0x%llx sym3=%s\n",
		tcb, op, a, b,
		(unsigned long long)(uintptr_t)ra[0], sym[0],
		(unsigned long long)(uintptr_t)ra[1], sym[1],
		(unsigned long long)(uintptr_t)ra[2], sym[2],
		(unsigned long long)(uintptr_t)ra[3], sym[3]);
}

kern_return_t semaphore_signal_trap_impl(
				mach_port_name_t signal_name)
{
	sem_trap_site("signal", (unsigned int)signal_name, 0);
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 113): non-blocking semaphore signalling -- the plane is
	// its home. A blocking operation could not go here: the plane is a single serialized slot serviced
	// inside the server's own loop pass, so a blocking call would stall every other request.
	// perf#30 (doc section 245): the plane remains the FIRST route because the plane now performs the signal DIRECTLY
	// (no synthesized Call, no thread, see the server's op 27u handler); the Ring RPC path stays as the fallback the
	// plane protocol itself defines.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_SEMAPHORE_SIGNAL,
			(uint64_t)(uint32_t)signal_name, 0, 0, 0, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_semaphore_signal(signal_name);
	}

	if (code < 0) {
		__simple_printf("semaphore_signal failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}
					      
kern_return_t semaphore_signal_all_trap_impl(
				mach_port_name_t signal_name)
{
	sem_trap_site("signal_all", (unsigned int)signal_name, 0);
	int code = -1;
	int planeStatus = -1;
	// perf#30 (doc section 245): plane first, for the same reason as the single-name signal above: the plane performs
	// it directly now, and the Ring RPC path remains the protocol's own fallback.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_SEMAPHORE_SIGNAL_ALL,
			(uint64_t)(uint32_t)signal_name, 0, 0, 0, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_semaphore_signal_all(signal_name);
	}

	if (code < 0) {
		__simple_printf("semaphore_signal_all failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_signal_thread_trap_impl(
				mach_port_name_t signal_name,
				mach_port_name_t thread_name)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t semaphore_wait_trap_impl(
				mach_port_name_t wait_name)
{
	sem_trap_site("wait", (unsigned int)wait_name, 0);
	int code = dserver_rpc_semaphore_wait(wait_name);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_wait failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_wait_signal_trap_impl(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name)
{
	sem_trap_site("wait_signal", (unsigned int)wait_name, (unsigned int)signal_name);
	int code = dserver_rpc_semaphore_wait_signal(wait_name, signal_name);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_wait_signal failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_timedwait_trap_impl(
				mach_port_name_t wait_name,
				unsigned int sec,
				clock_res_t nsec)
{
	sem_trap_site("timedwait", (unsigned int)wait_name, (unsigned int)sec);
	int code = dserver_rpc_semaphore_timedwait(wait_name, sec, nsec);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_timedwait failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t semaphore_timedwait_signal_trap_impl(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name,
				unsigned int sec,
				clock_res_t nsec)
{
	sem_trap_site("timedwait_signal", (unsigned int)wait_name, (unsigned int)signal_name);
	int code = dserver_rpc_semaphore_timedwait_signal(wait_name, signal_name, sec, nsec);

	if (code < 0) {
		if (code == -LINUX_EINTR) {
			return KERN_ABORTED;
		}
		__simple_printf("semaphore_timedwait_signal failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t clock_sleep_trap_impl(
				mach_port_name_t clock_name,
				sleep_type_t sleep_type,
				int sleep_sec,
				int sleep_nsec,
				mach_timespec_t	*wakeup_time)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t _kernelrpc_mach_vm_allocate_trap_impl(
				mach_port_name_t target,
				mach_vm_offset_t *addr,
				mach_vm_size_t size,
				int flags)
{
	if (target != 0 && target != mach_task_self())
	{
		int code = dserver_rpc_mach_vm_allocate(target, addr, size, flags);

		if (code < 0) {
			__simple_printf("mach_vm_allocate failed (internally): %d\n", code);
			__simple_abort();
		}

		return code;
	}
	else
	{
		return _kernelrpc_mach_vm_map_trap_impl(target, addr,
				size, 0, flags, VM_PROT_READ | VM_PROT_WRITE);
	}
}

kern_return_t _kernelrpc_mach_vm_deallocate_trap_impl(
				mach_port_name_t target,
				mach_vm_address_t address,
				mach_vm_size_t size
)
{
	int ret;

	if (target != 0 && target != mach_task_self())
	{
		// perf #18 P8 D5 (dar-1il.3.2.2): vm_deallocate of ANOTHER task's address space goes to the
		// server, whose vm_map_remove can drive a munmap S2C upcall back to THIS caller -- the exact
		// caller-S2C shape that wedges a simple-ring-parked thread (dar-1il.1). The DUPLEX lane lets the
		// caller pump that munmap S2C on its own thread while parked for the final reply. Try it FIRST
		// (a strict no-op unless the per-command hatch DARLING_GUEST_DUPLEX_VM_DEALLOCATE=1 is set AND the
		// VM_DEALLOCATE cap is negotiated). On a valid round-trip `code` is the kern_return_t, used
		// verbatim. On ANY transport miss or a server PRE-MUTATION decline it returns nonzero and we
		// UDS-fall-back -- safe, because the server declines BEFORE dispatching (the op runs exactly once).
		// Folded away entirely unless -DDARLING_RING_TRANSPORT.
		int code;
		if (__dserver_ring_mach_vm_deallocate_duplex(target, address, size, &code) != 0) {
			code = dserver_rpc_mach_vm_deallocate(target, address, size);
		}

		if (code < 0) {
			__simple_printf("mach_vm_deallocate failed (internally): %d\n", code);
			__simple_abort();
		}

		return code;
	}
	else
	{
		// XNU returns KERN_INVALID_ARGUMENT for address overflow, 
		// and allows NULL address if size is 0.
		if (address + size < address)
		{
			return KERN_INVALID_ARGUMENT;
		}

		if (size == (mach_vm_offset_t)0)
		{
			return KERN_SUCCESS;
		}

		ret = munmap((void*)address, size);

		if (ret == -1)
			return KERN_FAILURE;

		return KERN_SUCCESS;
	}
}

kern_return_t _kernelrpc_mach_vm_protect_trap_impl(
				mach_port_name_t target,
				mach_vm_address_t address,
				mach_vm_size_t size,
				boolean_t set_maximum,
				vm_prot_t new_protection
)
{
	int prot = 0;
	int ret;

	if (target != 0 && target != mach_task_self())
		return MACH_SEND_INVALID_DEST;

	if (new_protection & VM_PROT_READ)
		prot |= PROT_READ;
	if (new_protection & VM_PROT_WRITE)
		prot |= PROT_WRITE;
	if (new_protection & VM_PROT_EXECUTE)
		prot |= PROT_EXEC;

	ret = mprotect((void*)address, size, prot);
	if (ret == -1)
		return KERN_FAILURE;

	return KERN_SUCCESS;
}

kern_return_t _kernelrpc_mach_vm_map_trap_impl(
				mach_port_name_t target,
				mach_vm_offset_t *address,
				mach_vm_size_t size,
				mach_vm_offset_t mask,
				int flags,
				vm_prot_t cur_protection
)
{
	// We cannot allocate memory in other processes
	if (target != 0 && target != mach_task_self())
		return KERN_FAILURE;

	void* addr;
	int prot = 0;
	int posix_flags = MAP_ANON | MAP_PRIVATE;

	if (cur_protection & VM_PROT_READ)
		prot |= PROT_READ;
	if (cur_protection & VM_PROT_WRITE)
		prot |= PROT_WRITE;
	if (cur_protection & VM_PROT_EXECUTE)
		prot |= PROT_EXEC;

	if (!(flags & VM_FLAGS_ANYWHERE))
		posix_flags |= MAP_FIXED;
	if ((flags >> 24) == VM_MEMORY_REALLOC)
		addr = (void*)__linux_mremap(((char*)*address) - 0x1000, 0x1000, 0x1000 + size, 0, NULL);
	else
		addr = mmap((void*)*address, size, prot, posix_flags, -1, 0);
	
	if (addr == MAP_FAILED)
	{
		return KERN_FAILURE;
	}
	
	if (mask && ( ((uintptr_t)addr) & mask) != 0)
	{
		uintptr_t boundary, q, diff, iaddr;
		
		// Alignment was requested, but we couldn't get it the easy way
		munmap(addr, size);
		
		// This may not work for some crazy masks. Consider using __builtin_clz().
		boundary = mask + 1;
		
		iaddr = (uintptr_t)mmap((void*)*address, size + boundary, prot, posix_flags, -1, 0);
		if (iaddr == (uintptr_t) MAP_FAILED)
			return KERN_FAILURE;
		
		q = (iaddr + (boundary-1)) / boundary * boundary;
		diff = q - iaddr;
		
		if (diff > 0)
			munmap((void*)iaddr, diff);
		if (boundary - diff > 0)
			munmap((void*) (q + size), boundary - diff);
		
		addr = (void*) q;
	}

	*address = (uintptr_t)addr;
	return KERN_SUCCESS;
}

kern_return_t _kernelrpc_mach_port_allocate_trap_impl(
				mach_port_name_t target,
				mach_port_right_t right,
				mach_port_name_t *name
)
{
	// perf#30 DIAGNOSIS (plumbing check): this call is made by every workload iteration and its server-side
	// RECV is on the tape, so a print here proves libsystem_kernel's trap body is the code the guest runs.
	static int allocProbe = -1;
	if (allocProbe < 0) { const char* _t = getenv("DARLING_GUEST_ALLOC_PROBE"); allocProbe = (_t && _t[0] == '1') ? 1 : 0; }
	if (allocProbe) { __simple_printf("[allocprobe]\n"); }
	int code;
	// perf #18 P5-bulk (dar-1il.1): ride the ring (Tier-1 generic fiber path) -- byte-identical to
	// UDS, the allocated name is written into guest memory via `name` exactly as before; the reply
	// is header-only. On any ring miss, fall back to UDS. Folded away unless -DDARLING_RING_TRANSPORT.
	if (__dserver_ring_mach_port_allocate(target, right, (uint64_t)(uintptr_t)name, &code) != 0) {
		code = dserver_rpc_mach_port_allocate(target, right, name);
	}

	if (code < 0) {
		__simple_printf("mach_port_allocate failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}


kern_return_t _kernelrpc_mach_port_destroy_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name
)
{
	int code = dserver_rpc_mach_port_destruct(target, name, 0, 0);

	if (code < 0) {
		__simple_printf("mach_port_destroy failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_deallocate_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name
)
{
	// perf #18 P5-bulk (dar-1il.1): mach_port_deallocate is NOT on the SIMPLE ring -- destroying a port
	// backing a mapped region drives a vm-munmap S2C upcall to THIS thread, which a simple-ring-parked
	// (futex-waiting, non-recvmsg) caller cannot service -> deadlock. (See DSERVER_RING_C2S_OPCODES.)
	//
	// perf #18 P8 D4 (dar-1il.3.2.1): the DUPLEX lane fixes exactly that -- the caller pumps the munmap
	// S2C on its own thread while parked for the final reply. Try the duplex lane FIRST (it is a strict
	// no-op unless the per-command hatch DARLING_GUEST_DUPLEX_DEALLOCATE=1 is set AND the cap is
	// negotiated). On a valid duplex round-trip `code` is the kern_return_t and we use it verbatim. On
	// ANY transport miss or a server PRE-MUTATION decline it returns nonzero and we UDS-fall-back --
	// safe, because the server declines BEFORE dispatching (no mutation), so the op runs exactly once.
	// Folded away entirely unless -DDARLING_RING_TRANSPORT.
	int code;
	if (__dserver_ring_mach_port_deallocate_duplex(target, name, &code) != 0) {
		code = dserver_rpc_mach_port_deallocate(target, name);
	}

	if (code < 0) {
		__simple_printf("mach_port_deallocate failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_mod_refs_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_right_t right,
				mach_port_delta_t delta
)
{
	// perf #18 P5-bulk audit (dar-1il.2): mach_port_mod_refs is DELIBERATELY NOT ring-routed.
	// It is destroy-CAPABLE: mod_refs(right, delta<0) dropping the last user-ref of a receive right
	// destroys the port, and destroying a port that backs a mapped region drives a vm munmap
	// server-to-client (S2C) upcall to THIS thread -- the SAME hazard that sank mach_port_deallocate.
	// A thread parked on a ring reply is not in a recvmsg and cannot service an S2C call, so the
	// server microthread would block on the S2C reply while the guest blocks in the ring futex-wait
	// -> deadlock. The hazard is a SIDE EFFECT of certain (negative-delta, last-ref) args, not the
	// return code, and cannot be decided before the ipc_space lock is held and the refcount known
	// (i.e. after mutation begins), so it stays on UDS -- where the caller's recvmsg services the
	// S2C -- until a proven-safe subset is gated. (See DSERVER_RING_C2S_OPCODES, rpc-supplement.h.)
	int code = -1;
	int planeStatus = -1;
	// perf#30 DIAGNOSIS: name the two ends of the ONE call the workload stops in. Without these, "the workload
	// never reached the trap" and "the trap ran and its answer is what stopped the workload" are the same
	// observation from the outside (the workload's own next mark never appears either way).
	__simple_printf("[modrefs-entry target=%u name=%u right=%d delta=%d]\n",
		(unsigned)target, (unsigned)name, (int)right, (int)delta);
	// HOST-DISPOSITION PROBE, next to the point where the workload stops. MEASURED NEED: the guest's own
	// sigaction API says SIGSEGV has a real handler, SIGSEGV is never blocked, and yet the kernel never enters the
	// wrapper that runs that handler before the process dies of SIGSEGV. The guest's table is not the question --
	// the HOST disposition is -- so this reads it with a raw rt_sigaction query (oldact only, nothing is changed)
	// and prints the handler POINTER: 0 is SIG_DFL, 1 is SIG_IGN, anything else is a real handler. Bounded, and it
	// names the actor by what it leaves behind: a last line with 0 next to a death by SIGSEGV means something
	// replaced the handler without going through the API.
	{
		static int emitted_disp = 0;
		if (emitted_disp < 30) {
			++emitted_disp;
			struct linux_sigaction old_sa;
			long q = LINUX_SYSCALL(__NR_rt_sigaction, 11 /* LINUX_SIGSEGV */, NULL, &old_sa, sizeof(old_sa.sa_mask));
			extern void* dw_sig_wrapper_addr;
			extern void handler_linux_to_bsd(int, struct linux_siginfo*, void*);
			extern void sigexc_handler(int, struct linux_siginfo*, void*);
			const void* disp = (const void*)old_sa.sa_sigaction;
			// The KERNEL mask, not the guest's API view: Darling masks signals with raw rt_sigprocmask calls in its
			// own machinery, which an API-level probe cannot see. A hardware fault whose signal is masked takes the
			// default action -- a silent death with no handler entry, which is exactly the shape being chased.
			unsigned char curmask[8] = {0};
			long mq = LINUX_SYSCALL(__NR_rt_sigprocmask, 0, NULL, curmask, sizeof(curmask));
			int segv_masked = (mq == 0)
				? (int)((curmask[(11 - 1) >> 3] >> ((11 - 1) & 7)) & 1) : -1;
			__simple_fprintf(2, "[segvdisp q=%ld handler=%p is_wrapper=%d is_bsd=%d is_sigexc=%d segv_masked=%d seq=%d]\n",
				q, disp,
				(int)(disp == dw_sig_wrapper_addr),
				(int)(disp == (const void*)&handler_linux_to_bsd),
				(int)(disp == (const void*)&sigexc_handler),
				segv_masked,
				emitted_disp);
		}
	}
	// perf#30 (directive section 2, doc section 112): early Mach port operation -- the process
	// MANAGEMENT PLANE is its home. The server runs the ORDINARY Call, so the semantics exist once
	// (section 15). Only `planeStatus == -1` (not published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_MOD_REFS,
			(uint64_t)(uint32_t)target, (uint64_t)(uint32_t)name, (uint64_t)(uint32_t)right, (uint64_t)(uint32_t)delta, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	// perf#30 DIAGNOSIS: the death is INSIDE this call and the two ends of it print, so the next question is which
	// half -- the transport attempt itself, or the datagram stub after the plane refused. MEASURED need: with the
	// plane refused (`DARLING_GUEST_PLANE_OFF=1`) `[modrefs-entry]` prints and `[modrefs-exit]` never does, which
	// covers both halves at once. These two marks split them; the transport's own per-call trace
	// (`DARLING_GUEST_RING_TRACE=1` -> `RING_TRACE gen ENTER/EXIT callnum=`) splits it again inside the stub.
	__simple_printf("[modrefs-plane-done status=%d]\n", (int)planeStatus);
	if (planeStatus == -1) {
		__simple_printf("[modrefs-fallback-enter target=%u name=%u]\n", (unsigned)target, (unsigned)name);
		// DUPLEX FIRST (perf#30 / dar-4cp9): mod_refs is destroy-capable and needs the caller to pump a munmap
		// upcall, which is exactly what the duplex lane provides. Only a pre-publish miss or a pre-mutation
		// DECLINE falls through to the ordinary RPC; a published request is never retried elsewhere.
		if (__dserver_ring_mach_port_mod_refs_duplex(target, name, right, delta, &code) != 0) {
			code = dserver_rpc_mach_port_mod_refs(target, name, right, delta);
		}
	}

	if (code < 0) {
		__simple_printf("mach_port_mod_refs failed (internally): %d\n", code);
		__simple_abort();
	}
	__simple_printf("[modrefs-exit code=%d plane=%d]\n", (int)code, (int)planeStatus);

	return code;
}

kern_return_t _kernelrpc_mach_port_move_member_trap_impl(
				mach_port_name_t target,
				mach_port_name_t member,
				mach_port_name_t after
)
{
	int code = -1;
	// perf#30 (doc sections 107/108, directive sections 2 and 15): this call is reached before the lane can
	// be relied on -- it was put on the lane routing table and MEASURED to fail there exactly as
	// pthread_canceled does -- so its home is the process MANAGEMENT PLANE, not the datagram. The server
	// runs the ordinary MachPortMoveMember Call, so there is one implementation of the semantics and this
	// is only a transport adapter. -1 from the plane means "not published / not completed", so only then
	// does the datagram run and nothing is ever retried after publication.
	{
		uint64_t reply0 = 0;
		int planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_MOVE_MEMBER,
			(uint64_t)target, (uint64_t)member, (uint64_t)after, 0, &reply0, 0);
		/* BOUNDED PLANE RETRY, WITHOUT THE DATAGRAM (dar-4cp9). MEASURED boot failure: a rpc-socket-DENIED
		 * with call=mach_port_move_member image=kernel, immediately followed by sigexc-fatal sig=6, i.e. this
		 * call answered -1 from the plane (nothing published), fell through to the datagram, and the hard
		 * socket gate denied that -- launchd then aborted. The BOUNDED RETRY NOW LIVES IN THE PLANE ENTRY POINT
		 * ITSELF (__dserver_plane_request_ex wraps ..._once with nine attempts), so every caller inherits it and
		 * this call no longer carries its own copy. The datagram attempt stays for the shapes that genuinely need
		 * it, but it is no longer the FIRST thing this call does after a failed publication. */
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (code == -1) {
		code = dserver_rpc_mach_port_move_member(target, member, after);
	}

	if (code < 0) {
		__simple_printf("mach_port_move_member failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_insert_right_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_name_t poly,
				mach_msg_type_name_t polyPoly
)
{
	int code;
	// perf #18 P5-bulk (dar-1il.1): ring Tier-1 (generic fiber path), UDS fallback on any miss.
	if (__dserver_ring_mach_port_insert_right(target, name, poly, polyPoly, &code) != 0) {
		code = dserver_rpc_mach_port_insert_right(target, name, poly, polyPoly);
	}

	if (code < 0) {
		__simple_printf("mach_port_insert_right failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_insert_member_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_name_t pset
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 112): early Mach port operation -- the process
	// MANAGEMENT PLANE is its home. The server runs the ORDINARY Call, so the semantics exist once
	// (section 15). Only `planeStatus == -1` (not published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_INSERT_MEMBER,
			(uint64_t)(uint32_t)target, (uint64_t)(uint32_t)name, (uint64_t)(uint32_t)pset, 0, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_insert_member(target, name, pset);
	}

	if (code < 0) {
		__simple_printf("mach_port_insert_member failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_extract_member_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_name_t pset
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 112): early Mach port operation -- the process
	// MANAGEMENT PLANE is its home. The server runs the ORDINARY Call, so the semantics exist once
	// (section 15). Only `planeStatus == -1` (not published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_EXTRACT_MEMBER,
			(uint64_t)(uint32_t)target, (uint64_t)(uint32_t)name, (uint64_t)(uint32_t)pset, 0, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_extract_member(target, name, pset);
	}

	if (code < 0) {
		__simple_printf("mach_port_extract_member failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_construct_trap_impl(
				mach_port_name_t target,
				mach_port_options_t *options,
				uint64_t context,
				mach_port_name_t *name
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 110): reached early like mach_port_move_member, so its home
	// is the process MANAGEMENT PLANE. Four parameters fill the four payload words; the server runs the
	// ORDINARY MachPortConstruct Call, so the semantics exist once (directive section 15). Only
	// `planeStatus == -1` (not published / not completed) falls back to the datagram, so a published call is
	// never retried.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_CONSTRUCT,
			(uint64_t)target, context, (uint64_t)(uintptr_t)name,
			(uint64_t)(uintptr_t)options, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_construct(target, options, context, name);
	}

	if (code < 0) {
		__simple_printf("mach_port_construct failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_destruct_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				mach_port_delta_t srdelta,
				uint64_t guard
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 111): reached early like mach_port_move_member and
	// mach_port_construct, so its home is the process MANAGEMENT PLANE. All four parameters fill the payload
	// words; the server runs the ORDINARY MachPortDestruct Call, so the semantics exist once (section 15).
	// Only `planeStatus == -1` (not published / not completed) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_DESTRUCT,
			(uint64_t)target, (uint64_t)name, (uint64_t)(uint32_t)srdelta, guard, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_destruct(target, name, srdelta, guard);
	}

	if (code < 0) {
		__simple_printf("mach_port_destruct failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_guard_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				uint64_t guard,
				boolean_t strict
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 112): early Mach port operation -- the process
	// MANAGEMENT PLANE is its home. The server runs the ORDINARY Call, so the semantics exist once
	// (section 15). Only `planeStatus == -1` (not published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_GUARD,
			(uint64_t)(uint32_t)target, (uint64_t)(uint32_t)name, (uint64_t)(uintptr_t)guard, (uint64_t)(uint32_t)strict, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_guard(target, name, guard, strict);
	}

	if (code < 0) {
		__simple_printf("mach_port_guard failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t _kernelrpc_mach_port_unguard_trap_impl(
				mach_port_name_t target,
				mach_port_name_t name,
				uint64_t guard
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 112): early Mach port operation -- the process
	// MANAGEMENT PLANE is its home. The server runs the ORDINARY Call, so the semantics exist once
	// (section 15). Only `planeStatus == -1` (not published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_UNGUARD,
			(uint64_t)(uint32_t)target, (uint64_t)(uint32_t)name, (uint64_t)(uintptr_t)guard, 0, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_unguard(target, name, guard);
	}

	if (code < 0) {
		__simple_printf("mach_port_unguard failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t thread_get_special_reply_port_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_thread_get_special_reply_port(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
};

kern_return_t _kernelrpc_mach_port_request_notification_impl(
	ipc_space_t task,
	mach_port_name_t name,
	mach_msg_id_t msgid,
	mach_port_mscount_t sync,
	mach_port_name_t notify,
	mach_msg_type_name_t notifyPoly,
	mach_port_name_t* previous
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 1, doc section 206): the hard oracle named this call as the FIRST per-thread
	// socket dependency -- reached from the main thread before a lane can be relied on -- so the process MANAGEMENT
	// PLANE is its home (directive section 2: a call reached too early does not "stay on UDS"; it moves). The server
	// runs the ORDINARY Call, so the semantics exist once. Four 32-bit request words travel two per payload word and
	// the OUT pointer `previous` is passed as the GUEST ADDRESS for the Call's own writeMemory. Only
	// `planeStatus == -1` (nothing published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_REQUEST_NOTIFICATION,
			((uint64_t)(uint32_t)task) | (((uint64_t)(uint32_t)name) << 32),
			((uint64_t)(uint32_t)msgid) | (((uint64_t)(uint32_t)sync) << 32),
			((uint64_t)(uint32_t)notify) | (((uint64_t)(uint32_t)notifyPoly) << 32),
			(uint64_t)(uintptr_t)previous, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_request_notification(task, name, msgid, sync, notify, notifyPoly, previous);
	}

	if (code < 0) {
		__simple_printf("mach_port_request_notification failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t _kernelrpc_mach_port_get_attributes_impl(
	mach_port_name_t target,
	mach_port_name_t name,
	mach_port_flavor_t flavor,
	mach_port_info_t port_info_out,
	mach_msg_type_number_t* port_info_outCnt
)
{
	int code = dserver_rpc_mach_port_get_attributes(target, name, flavor, port_info_out, port_info_outCnt);

	if (code < 0) {
		__simple_printf("mach_port_get_attributes failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t _kernelrpc_mach_port_type_impl(
	ipc_space_t task,
	mach_port_name_t name,
	mach_port_type_t* ptype
)
{
	int code = -1;
	int planeStatus = -1;
	// perf#30 (directive section 2, doc section 112): early Mach port operation -- the process
	// MANAGEMENT PLANE is its home. The server runs the ORDINARY Call, so the semantics exist once
	// (section 15). Only `planeStatus == -1` (not published) falls back to the datagram.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_MACH_PORT_TYPE,
			(uint64_t)(uint32_t)task, (uint64_t)(uint32_t)name, (uint64_t)(uintptr_t)ptype, 0, &reply0, 0);
		if (planeStatus != -1) {
			code = (int)(int32_t)(uint32_t)reply0;
		}
	}
	if (planeStatus == -1) {
		code = dserver_rpc_mach_port_type(task, name, ptype);
	}

	if (code < 0) {
		__simple_printf("mach_port_type failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
};

kern_return_t macx_swapon_impl(
				uint64_t filename,
				int flags,
				int size,
				int priority)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_swapoff_impl(
				uint64_t filename,
				int flags)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_triggers_impl(
				int hi_water,
				int low_water,
				int flags,
				mach_port_t alert_port)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_backing_store_suspend_impl(
				boolean_t suspend)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

kern_return_t macx_backing_store_recovery_impl(
				int pid)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

extern void __linux_sched_yield();
boolean_t swtch_pri_impl(int pri)
{
	__linux_sched_yield();
	return 0;
}

boolean_t swtch_impl(void)
{
	__linux_sched_yield();
	return 0;
}

extern int __linux_nanosleep(struct timespec* tv, struct timespec* rem);
kern_return_t syscall_thread_switch_impl(
				mach_port_name_t thread_name,
				int option,
				mach_msg_timeout_t option_time)
{
	struct timespec tv = {
		.tv_sec = 0,
		.tv_nsec = 1000000
	};
	// Sleep for 1ms
	__linux_nanosleep(&tv, &tv);

	// TODO: we could implement this with yield_to() in LKM
	return KERN_SUCCESS;
}

static cached_port_name_t __task_self_trap_rpc(void)
{
	unsigned int port_name;
	// Return a failed published request as NULL; the cache does not retain failures.
	// Only a pre-publication miss may use UDS for this invocation.
	int ring_code = __dserver_ring_task_self_trap(&port_name);
	if (ring_code >= 0) {
		return ring_code == 0 ? port_name : MACH_PORT_NULL;
	}
	if (dserver_rpc_task_self_trap(&port_name) != 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

mach_port_name_t task_self_trap_impl(void)
{
	// perf #7: the task self port is immutable per process; serve it from the cache
	// (filled by one real RPC, reset on fork via __darling_reset_cached_self_ports).
	mach_port_name_t self = cached_self_port_get(&__task_self_port_cache, __task_self_trap_rpc);
	// perf #18 P8 D3 (dar-1il.3.1.1): one-shot DUPLEX-lane selftest, driven here because this is an
	// early trap with the ring already attached. A strict no-op unless the marker file
	// /private/tmp/.dring-duplex-go exists (see __dserver_ring_maybe_run_duplex_selftest); it is
	// consumed by the first guest to claim it, so it never perturbs a normal boot. Folds away entirely
	// when the dylib is built without the ring.
	__dserver_ring_maybe_run_duplex_selftest();
	// perf #18 P8 D6 (caller-S2C sideband): one-shot synthetic WARM real-munmap proof, driven here for the
	// same reason (early trap, ring attached). Strict no-op unless the marker /private/tmp/.dring-d6-munmap-go
	// exists. `self` is this task's mach_task_self() name -> the server resolves it to current_task() and
	// frees our just-mapped page = a REAL caller-S2C munmap over the duplex lane.
	__dserver_ring_maybe_run_d6_munmap_proof(self);
	return self;
}

/*
 *	Obsolete interfaces.
 */

kern_return_t task_for_pid_impl(
				mach_port_name_t target_tport,
				int pid,
				mach_port_name_t *t)
{
	int code = dserver_rpc_task_for_pid(target_tport, pid, t);

	if (code < 0) {
		__simple_printf("task_for_pid failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t task_name_for_pid_impl(
				mach_port_name_t target_tport,
				int pid,
				mach_port_name_t *tn)
{
	int code = dserver_rpc_task_name_for_pid(target_tport, pid, tn);

	if (code < 0) {
		__simple_printf("task_name_for_pid failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t pid_for_task_impl(
				mach_port_name_t t,
				int *x)
{
	int code = dserver_rpc_pid_for_task(t, x);

	if (code < 0) {
		__simple_printf("pid_for_task failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t mach_generate_activity_id_impl(mach_port_name_t task, int i, uint64_t* id)
{
	UNIMPLEMENTED_TRAP();
	return KERN_FAILURE;
}

mach_port_name_t mk_timer_create_impl(void)
{
	unsigned int port_name;
	if (dserver_rpc_mk_timer_create(&port_name) < 0) {
		port_name = MACH_PORT_NULL;
	}
	return port_name;
}

kern_return_t mk_timer_destroy_impl(mach_port_name_t name)
{
	int code = dserver_rpc_mk_timer_destroy(name);

	if (code < 0) {
		__simple_printf("mk_timer_destroy failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t mk_timer_arm_impl(mach_port_name_t name, uint64_t expire_time)
{
	int code = dserver_rpc_mk_timer_arm(name, expire_time);

	if (code < 0) {
		__simple_printf("mk_timer_arm failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}

kern_return_t mk_timer_cancel_impl(mach_port_name_t name, uint64_t *result_time)
{
	int code = dserver_rpc_mk_timer_cancel(name, result_time);

	if (code < 0) {
		__simple_printf("mk_timer_cancel failed (internally): %d\n", code);
		__simple_abort();
	}

	return code;
}
