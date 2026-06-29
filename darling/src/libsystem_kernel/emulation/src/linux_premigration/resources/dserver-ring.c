// perf #18 (dar-dar6x4-perf-5dq.30) P3: GUEST-side shared-memory ring transport.
//
// Builds the guest's ring memfd, negotiates it via the ring_attach RPC, and provides a
// fast path for eligible calls (P3: task_self_trap) that publishes a request onto the c2s
// ring + wakes the server (via the wake eventfd the server handed back) and waits for the
// reply on the s2c ring -- skipping the UDS sendmsg/recvmsg round-trip that the profile
// showed is ~90% empty cross-process wakeup latency.
//
// LIBC-FREE: raw LINUX_SYSCALL only, exactly like the rest of the emulation layer. Entire
// file compiles to nothing unless DARLING_RING_TRANSPORT is defined.
//
// P3 SCOPE (deliberately minimal, single-trust-boundary-exercise):
//   * ONE ring per process, owned by the thread that first attaches it. Other threads see a
//     foreign owner and fall back to UDS (full per-thread rings are P4). This sidesteps
//     guest TLS (which is fragile this early in the emulation layer) while staying correct:
//     a non-owner never touches the ring.
//   * Only the no-arg port traps (task_self_trap, mach_reply_port) ride the ring; the server's
//     C2S service loop allowlists the same. task_self_trap is cached per-process (perf #7) so
//     it's correctness-first; mach_reply_port is the uncached hot op that exercises the win.
//   * Adaptive wait: bounded spin (reusing the DARLING_GUEST_RECVSPIN budget) then a
//     cross-process FUTEX_WAIT on s2c_futex. Server wakes via FUTEX_WAKE (non-private).

#ifdef DARLING_RING_TRANSPORT

// Make the ring ABI (structs + SPSC helpers) visible; the server-only attach-check is gated
// out (we never validate our own ring -- the SERVER is the trust boundary).
#define DSERVER_RING_TRANSPORT 1
#define DSERVER_RING_NO_ATTACH_CHECK 1

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc-supplement.h>

#include <stdint.h>
#include <stdbool.h>

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);

// The generated ring_attach wrapper.
extern int dserver_rpc_ring_attach(int ring_fd, uint64_t mapping_size, uint32_t* out_reject_reason, int* out_wake_fd);

// --- ring geometry (must satisfy dserver_ring_shm_validate on the server) -----------------
#define GR_SLOT_SIZE   128u   // >= sizeof(slot)+reply; in [64,4096]
#define GR_SLOT_COUNT  8u     // power of two in [2,1024]

#ifndef DARLING_GUEST_RECVSPIN
#define DARLING_GUEST_RECVSPIN 512
#endif

// futex op constants (avoid pulling a libc header; cross-PROCESS so NO private flag).
#define GR_FUTEX_WAIT 0
#define GR_FUTEX_WAKE 1

// --- process-wide ring state (owned by the first attaching thread) ------------------------
static int      g_ring_state = 0;        // 0=untried, 1=attached, -1=failed (UDS forever)
static void*    g_ring_map = 0;
static uint64_t g_ring_size = 0;
static int      g_wake_fd = -1;
static int      g_owner_tid = 0;         // gettid of the thread that owns the ring
static uint32_t g_seq = 1;               // monotonic request seq (single-owner -> no race)

static dserver_ring_shm_t* gr_cb(void)  { return (dserver_ring_shm_t*)g_ring_map; }
static dserver_ring_t* gr_c2s(void)     { return (dserver_ring_t*)((char*)g_ring_map + gr_cb()->c2s_ring_off); }
static dserver_ring_t* gr_s2c(void)     { return (dserver_ring_t*)((char*)g_ring_map + gr_cb()->s2c_ring_off); }

static inline void gr_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#elif defined(__aarch64__)
	__asm__ __volatile__("yield");
#else
	LINUX_SYSCALL0(__NR_sched_yield);
#endif
}

void __dserver_ring_postfork_reset(void) {
	// the parent's mapping + wake fd do not carry meaningful ownership into the child; drop
	// everything and let the child re-attach lazily on its next eligible call.
	if (g_ring_map && g_ring_size) {
		LINUX_SYSCALL(__NR_munmap, g_ring_map, g_ring_size);
	}
	if (g_wake_fd >= 0) {
		LINUX_SYSCALL1(__NR_close, g_wake_fd);
	}
	g_ring_state = 0;
	g_ring_map = 0;
	g_ring_size = 0;
	g_wake_fd = -1;
	g_owner_tid = 0;
	g_seq = 1;
}

bool __dserver_ring_try_attach(void) {
	if (g_ring_state == 1) {
		return (int)LINUX_SYSCALL(__NR_gettid) == g_owner_tid;
	}
	if (g_ring_state == -1) {
		return false;
	}

	// Lay out: [control block][c2s ring][s2c ring], each ring 64-aligned.
	uint64_t hdr = sizeof(dserver_ring_shm_t);
	uint64_t ring_span = sizeof(dserver_ring_t) + (uint64_t)GR_SLOT_COUNT * GR_SLOT_SIZE;
	uint64_t c2s_off = (hdr + 63u) & ~63ull;
	uint64_t s2c_off = (c2s_off + ring_span + 63u) & ~63ull;
	uint64_t total   = (s2c_off + ring_span + 63u) & ~63ull;

	// memfd_create("dring", MFD_CLOEXEC=0x1)
	long memfd = LINUX_SYSCALL(__NR_memfd_create, "dring", 0x1u);
	if (memfd < 0) { g_ring_state = -1; return false; }
	if (LINUX_SYSCALL(__NR_ftruncate, memfd, total) < 0) {
		LINUX_SYSCALL1(__NR_close, memfd);
		g_ring_state = -1; return false;
	}

	// map RW shared
#ifdef __NR_mmap2
	void* map = (void*)LINUX_SYSCALL(__NR_mmap2, 0, total, 0x1 | 0x2 /*PROT_READ|WRITE*/, 0x1 /*MAP_SHARED*/, memfd, 0);
#else
	void* map = (void*)LINUX_SYSCALL(__NR_mmap, 0, total, 0x1 | 0x2, 0x1, memfd, 0);
#endif
	if ((unsigned long)map > (unsigned long)-4096) {
		LINUX_SYSCALL1(__NR_close, memfd);
		g_ring_state = -1; return false;
	}

	// A freshly ftruncate'd memfd is zero-filled by the kernel, so the rings/control block
	// start zeroed (head==tail==0 == empty, futex words 0); we only fill the cb fields.
	dserver_ring_shm_t* cb = (dserver_ring_shm_t*)map;
	cb->magic = DSERVER_RING_MAGIC;
	cb->abi_version = DSERVER_RING_ABI_VERSION;
	cb->slot_size = (uint16_t)GR_SLOT_SIZE;
	cb->slot_count = GR_SLOT_COUNT;
	cb->arena_off = 0;
	cb->arena_size = 0;
	cb->c2s_ring_off = (uint32_t)c2s_off;
	cb->s2c_ring_off = (uint32_t)s2c_off;
	cb->total_size = (uint32_t)total;
	cb->guest_tid = (int32_t)LINUX_SYSCALL(__NR_gettid); // server cross-checks vs SCM nsid
	// perf #18 P4 wake-model words. The memfd is zero-filled, so these are already 0, but be
	// explicit: server_state starts SLEEPING_EPOLL (== 0) so we doorbell until the server first
	// publishes ACTIVE_POLLING; no guest is parked yet so s2c_waiters starts 0.
	cb->server_state = DSERVER_RING_SRV_SLEEPING_EPOLL;
	cb->s2c_waiters = 0;

	// negotiate over UDS: hand the memfd to the server. It validates + maps + returns the
	// wake eventfd (or a non-zero reject reason).
	uint32_t reject = 0;
	int wake_fd = -1;
	int rc = dserver_rpc_ring_attach((int)memfd, total, &reject, &wake_fd);

	// we no longer need the memfd ourselves (our mapping holds a reference).
	LINUX_SYSCALL1(__NR_close, memfd);

	if (rc != 0 || reject != dserver_ring_ok || wake_fd < 0) {
		LINUX_SYSCALL(__NR_munmap, map, total);
		if (wake_fd >= 0) LINUX_SYSCALL1(__NR_close, wake_fd);
		g_ring_state = -1;
		return false;
	}

	g_ring_map = map;
	g_ring_size = total;
	g_wake_fd = wake_fd;
	g_owner_tid = (int)LINUX_SYSCALL(__NR_gettid);
	g_ring_state = 1;
	return true;
}

// Wake the server -- CONDITIONALLY (perf #18 P4). We just published a request. The server only
// needs a doorbell if it is not actively polling its rings; while it spins (ACTIVE_POLLING) it
// will see our new c2s tail on its own, so the eventfd write is pure overhead and we skip it.
// dserver_ring_guest_should_doorbell() reads the server-published state with acquire ordering;
// a stale read at worst costs one redundant write, never a missed wake (an old/0 value ==
// SLEEPING_EPOLL == "doorbell", the safe direction).
static void gr_wake_server(void) {
	if (!dserver_ring_guest_should_doorbell(gr_cb())) {
		return; // server is draining rings; it'll pick up our request without a syscall
	}
	uint64_t one = 1;
	LINUX_SYSCALL(__NR_write, g_wake_fd, &one, sizeof(one));
}

// Wait for a reply on s2c: bounded spin, then cross-process FUTEX_WAIT on s2c_futex.
// Returns a pointer to the published reply slot (NULL on give-up so the caller UDS-falls-back).
//
// perf #18 P4: the hot path is the spin -- if the server replies within DARLING_GUEST_RECVSPIN
// iterations we return without touching the kernel AND without ever advertising ourselves as a
// waiter, so the server's conditional FUTEX_WAKE is a no-op too (zero syscalls round-trip). Only
// when we fall through to the slow path do we set s2c_waiters before parking, so the server knows
// to wake us; we clear it on the way out. The bit is set BEFORE the pre-sleep ring recheck, so the
// server can never publish-then-skip-wake while we're committed to sleeping (it reads the bit
// after publishing; if it sees 0 we hadn't slept yet and are still spinning the recheck).
static dserver_ring_slot_t* gr_wait_reply(void) {
	dserver_ring_t* s2c = gr_s2c();
	for (int i = 0; i < (DARLING_GUEST_RECVSPIN); ++i) {
		dserver_ring_slot_t* rep = dserver_ring_consumer_begin(s2c, GR_SLOT_SIZE, GR_SLOT_COUNT);
		if (rep) return rep;
		gr_relax();
	}
	// Slow path: advertise ourselves as a parked waiter so the server's conditional FUTEX_WAKE
	// fires, then sleep on the futex until it bumps the word. Re-check after each wake.
	uint32_t* word = &gr_cb()->s2c_futex;
	uint32_t* waiters = &gr_cb()->s2c_waiters;
	__atomic_store_n(waiters, 1u, __ATOMIC_RELEASE);
	dserver_ring_slot_t* result = 0;
	for (int guard = 0; guard < 100000; ++guard) {
		uint32_t observed = __atomic_load_n(word, __ATOMIC_ACQUIRE);
		dserver_ring_slot_t* rep = dserver_ring_consumer_begin(s2c, GR_SLOT_SIZE, GR_SLOT_COUNT);
		if (rep) { result = rep; break; }
		// FUTEX_WAIT(word, observed): sleeps only if *word still == observed (no lost wake).
		long r = LINUX_SYSCALL(__NR_futex, word, GR_FUTEX_WAIT, observed, 0, 0, 0);
		(void)r; // EAGAIN (value changed) / EINTR -> just re-loop and re-check the ring
	}
	// No longer parked -- the server may stop waking us. (Release so the clear is visible before
	// any subsequent request we publish.)
	__atomic_store_n(waiters, 0u, __ATOMIC_RELEASE);
	return result;
}

// Shared fast path for the no-arg, single-uint32-port-reply traps (task_self_trap,
// mach_reply_port). Publishes an empty-body request for `callnum`, wakes the server, waits for
// the reply, and validates seq+callnum+length before copying out the port. Returns 0 + writes
// *out_port on success, negative on any miss (caller UDS-falls-back). The reply convention
// ({reply_hdr.code, uint32 port}) is identical for both calls, so one helper covers them.
static int gr_port_trap(uint32_t callnum, uint32_t* out_port) {
	if (!__dserver_ring_try_attach()) {
		return -1; // no ring for this thread -> UDS fallback
	}

	dserver_ring_t* c2s = gr_c2s();
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -1; // ring full -> UDS fallback
	}
	uint32_t seq = g_seq++;
	req->callnum = callnum;
	req->seq = seq;
	req->length = 0;
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	dserver_ring_producer_publish(c2s);

	gr_wake_server();

	dserver_ring_slot_t* rep = gr_wait_reply();
	if (!rep) {
		return -1; // gave up waiting -> UDS fallback (the reply may still land; P3 single
		           // owner means the next attach re-syncs; acceptable for the first op)
	}

	// Validate the reply belongs to our request before trusting it.
	int rc = -1;
	if (rep->seq == seq && rep->callnum == callnum) {
		uint32_t inlineCap = GR_SLOT_SIZE - (uint32_t)sizeof(dserver_ring_slot_t);
		if (rep->length >= sizeof(dserver_ring_reply_hdr_t) + sizeof(uint32_t) && rep->length <= inlineCap) {
			char* payload = (char*)rep + sizeof(dserver_ring_slot_t);
			dserver_ring_reply_hdr_t* rh = (dserver_ring_reply_hdr_t*)payload;
			uint32_t port;
			memcpy(&port, payload + sizeof(dserver_ring_reply_hdr_t), sizeof(port));
			if (out_port) *out_port = port;
			rc = rh->code;
		}
	}
	dserver_ring_consumer_advance(gr_s2c());
	return rc;
}

int __dserver_ring_task_self_trap(uint32_t* out_port) {
	return gr_port_trap((uint32_t)dserver_callnum_task_self_trap, out_port);
}

int __dserver_ring_mach_reply_port(uint32_t* out_port) {
	return gr_port_trap((uint32_t)dserver_callnum_mach_reply_port, out_port);
}

#endif // DARLING_RING_TRANSPORT
