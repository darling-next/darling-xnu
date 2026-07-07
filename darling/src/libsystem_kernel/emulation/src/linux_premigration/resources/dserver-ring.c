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

#include <mach/kern_return.h>

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

// --- PER-THREAD ring lanes (perf #18 D16, dar-1il.11) -------------------------------------
//
// P3 shipped ONE process-wide ring owned by the first-attaching TID; every OTHER thread saw a foreign
// owner and fell back to UDS. D15a measured the cost: ~2053 POST-attach eligible calls scattered to UDS
// because the eligible-op traffic is multi-thread but the ring was single-thread. D16 gives EACH guest
// thread its own SPSC lane (its own memfd/mapping/wake-fd/seq), so a non-owner thread's eligible ops ride
// the ring instead of UDS. Each lane is still strictly SPSC (one guest thread <-> the server); we never
// share a ring across threads (that would reintroduce the producer race the SPSC correctness depends on
// NOT having). On lane exhaustion a thread cleanly UDS-falls-back -- never blocks, never shares.
//
// STORAGE = a fixed-max process-global TABLE indexed by hashed gettid (NOT __thread). __thread is unsafe
// this far below libSystem: the perf#9 sleep accountant (rpc-sleep-account.h) records "TLS aborts here
// pre-pthread", and P3 chose single-owner precisely to dodge guest TLS fragility. A static table keyed by
// TID keeps the SPSC-per-thread invariant (each live TID maps to exactly one lane) WITHOUT relying on the
// emulation layer's TLS machinery -- the storage mechanism is an impl detail; the per-thread SPSC lane is
// the invariant. The bookkeeping (active bit published LAST on acquire, generation bumped on every
// reclaim) is the contract pinned by tests/ring_multilane_gate_test.c (the dar-my8 exhaustive gate).
#ifndef GR_MAX_LANES
#define GR_MAX_LANES 128u  // fixed per-process cap; sized for the homebrew workload's thread fan-out.
#endif                     // exceeding it -> UDS fallback (logged once), never a shared lane.
                           // perf#18 D18a (task #68): raised 64->128. A 96-worker process actually wants
                           // ~97 lanes (96 workers + 1 runtime helper), so 64 exhausted ~39k eligible ops
                           // to UDS and 96 still 1202; 128 gives headroom -> exhausted=0, 100% ring, no
                           // regressions, +~2.5KB BSS/image + a lazy 4KB page per ATTACHED lane only.
                           // Right-sized, not infinite: >128 concurrent eligible-op threads still fall
                           // back (a future bead = lane reclaim on thread-exit). Guest-only + ABI-neutral
                           // (a lane is the same ring ABI attached N times; opcode-hash unaffected).

typedef struct {
	// `active` is the free/used marker AND the publish gate: a lane is usable iff active==1, and acquire
	// sets active=1 LAST (release order) so a concurrent lookup never sees a half-initialized lane.
	uint32_t active;       // 0 = free, 1 = live (atomic; published last on acquire, cleared first on release)
	uint32_t generation;   // bumped on every (re)claim so a recycled TID can't match a stale lane epoch
	int      state;        // 0=untried, 1=attached, -1=this lane failed (UDS for this thread)
	int      owner_tid;    // gettid of the owning thread
	void*    map;
	uint64_t size;
	int      wake_fd;
	uint32_t seq;          // monotonic request seq for THIS lane (single-owner -> no race)
} gr_lane_t;

static gr_lane_t g_lanes[GR_MAX_LANES];
static int       g_lanes_exhausted_logged = 0;

// perf #18 D17 (dar-1il.12): GUEST-side lane stats (RECON-only; plain process-global counters bumped on
// the slow attach path, NOT the hot publish path). Dumped to stderr once per process at clean exit when
// DARLING_GUEST_LANE_STATS=1 (the same libc-free stderr discipline as the duplex selftest; default OFF ->
// the dump function early-returns and these counters are simply never read). They answer the D17 C-vs-A
// question from the guest side: lanes_acquired (successful attaches in THIS process), lanes_exhausted
// (claims that found the table full -> UDS fallback = reason C if >0), lanes_reclaimed (a slot reused after
// a prior epoch -> generation bumped from nonzero).
static uint64_t g_stat_lanes_acquired = 0;
static uint64_t g_stat_lanes_exhausted = 0;
static uint64_t g_stat_lanes_reclaimed = 0;

static dserver_ring_shm_t* gr_cb(gr_lane_t* L)  { return (dserver_ring_shm_t*)L->map; }
static dserver_ring_t* gr_c2s(gr_lane_t* L)     { return (dserver_ring_t*)((char*)L->map + gr_cb(L)->c2s_ring_off); }
static dserver_ring_t* gr_s2c(gr_lane_t* L)     { return (dserver_ring_t*)((char*)L->map + gr_cb(L)->s2c_ring_off); }

typedef enum {
	GR_WAIT_COMPLETED = 0,
	GR_WAIT_COMMITTED_UNKNOWN = 1,
} gr_wait_state_t;

typedef struct {
	gr_wait_state_t state;
	dserver_ring_slot_t* slot;
} gr_wait_result_t;

// Find THIS thread's already-attached lane, or NULL. Probes from a hashed start so distinct TIDs spread
// across the table. A lane matches iff it is active for our TID (the active read is acquire-ordered, so
// if we observe active==1 the lane is fully initialized -- the gate's INVARIANT 1).
static gr_lane_t* gr_find_lane(int tid) {
	uint32_t start = ((uint32_t)tid * 2654435761u) % GR_MAX_LANES; // Knuth multiplicative hash
	for (uint32_t i = 0; i < GR_MAX_LANES; ++i) {
		gr_lane_t* L = &g_lanes[(start + i) % GR_MAX_LANES];
		if (__atomic_load_n(&L->active, __ATOMIC_ACQUIRE) == 1 && L->owner_tid == tid) {
			return L;
		}
	}
	return 0;
}

// Claim a FREE slot for THIS thread (active 0 -> claimed), or NULL if the table is full. The caller then
// fully initializes the lane and publishes active=1 LAST. Single-threaded per OS thread for its own
// claim, but two DIFFERENT threads may race for free slots concurrently, so the claim is a CAS on active
// (0 -> a transient "claiming" sentinel 2) to guarantee distinct slots; we settle it to 1 only after init.
static gr_lane_t* gr_claim_lane(int tid) {
	uint32_t start = ((uint32_t)tid * 2654435761u) % GR_MAX_LANES;
	for (uint32_t i = 0; i < GR_MAX_LANES; ++i) {
		gr_lane_t* L = &g_lanes[(start + i) % GR_MAX_LANES];
		uint32_t expected = 0;
		// CAS 0 -> 2 ("claiming"): wins the slot exclusively without yet advertising it as usable (==1).
		if (__atomic_compare_exchange_n(&L->active, &expected, 2u, false,
		                                __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
			// dar-j7e7: establish the honest "no fd" sentinel the instant we own the slot, BEFORE any
			// attach failure path can release it. The slot came from zero-init (wake_fd==0 == valid fd 0);
			// setting -1 now means an attach that bails between claim and fill never leaves a 0 that a
			// later reader/reset could mistake for a live fd. Fully redundant with the active-gated reset,
			// but keeps the field's invariant true at every lifecycle point (defence in depth).
			L->wake_fd = -1;
			return L;
		}
	}
	return 0; // table full -> caller UDS-falls-back
}

#ifdef DARLING_RING_PHASE_PROF
// perf #18 P6 (dar-aw2): guest-side rdtsc phase accountant. Pure diagnostic (default OFF, whole
// block compiles out). Accumulates TSC cycles for the guest-visible phases of the hot round-trip:
//   submit    = publish request + conditional doorbell (gr_wake_server)
//   roundtrip = time from after-submit until the reply is observed (server-side + wakeup latency)
//   observe   = validate + copy the port out of the reply slot
// and dumps mean cycles/phase to stderr once GR_PHASE_DUMP_AT samples accrue. Reuses the perf#9
// in-guest accountant pattern (rdtsc, NOT clock_gettime which wedges the guest this early).
#include <darling/emulation/common/simple.h>
#define GR_PHASE_DUMP_AT 5000
static unsigned long gr_ph_submit = 0, gr_ph_round = 0, gr_ph_observe = 0, gr_ph_total = 0;
static unsigned long gr_ph_n = 0;
static inline unsigned long gr_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
	unsigned hi, lo;
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long)hi << 32) | lo;
#else
	return 0;
#endif
}
static void gr_phase_maybe_dump(void) {
	if (gr_ph_n < GR_PHASE_DUMP_AT) return;
	__simple_fprintf(2, "[gr-phase] n=%lu mean cycles: submit=%lu roundtrip=%lu observe=%lu total=%lu\n",
		gr_ph_n, gr_ph_submit / gr_ph_n, gr_ph_round / gr_ph_n, gr_ph_observe / gr_ph_n, gr_ph_total / gr_ph_n);
	gr_ph_submit = gr_ph_round = gr_ph_observe = gr_ph_total = 0; gr_ph_n = 0;
}
#endif

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
	// fork() clones the parent's lane mappings + wake fds into the child, but they belong to the PARENT's
	// server-side threads -- the child must NOT reuse them. Drop EVERY lane (munmap + close), zero the
	// whole table, and let the child re-attach lazily, per thread, on its next eligible call. (The child
	// typically has just one thread right after fork; it will claim a fresh lane on demand.)
	for (uint32_t i = 0; i < GR_MAX_LANES; ++i) {
		gr_lane_t* L = &g_lanes[i];
		// dar-j7e7: free resources gated on the OWNERSHIP MARKER (active==1), NOT on the resource value.
		// g_lanes is `static` -> zero-initialized -> an un-attached lane has wake_fd==0 (NOT -1). The old
		// `if (L->wake_fd >= 0) close(...)` therefore ran close(0) for every untouched lane in the fork
		// child, destroying its stdin ("cannot duplicate fd 0" on the next exec). A lane owns its map +
		// wake_fd IFF acquire published it (active=1 published LAST); only then may the child release them.
		// This keys the teardown off the SAME publish marker acquire sets, symmetric to release.
		if (__atomic_load_n(&L->active, __ATOMIC_ACQUIRE) == 1) {
			if (L->map && L->size) {
				LINUX_SYSCALL(__NR_munmap, L->map, L->size);
			}
			if (L->wake_fd >= 0) {
				LINUX_SYSCALL1(__NR_close, L->wake_fd);
			}
		}
		// zero the lane completely: active=0 (free), generation back to 0 (a fresh post-fork epoch space).
		// wake_fd back to the HONEST -1 sentinel so a later read can never mistake the 0 default for fd 0.
		L->active = 0;
		L->generation = 0;
		L->state = 0;
		L->owner_tid = 0;
		L->map = 0;
		L->size = 0;
		L->wake_fd = -1;
		L->seq = 1;
	}
	g_lanes_exhausted_logged = 0;
}

// Attach a fresh ring lane for THIS thread: build the memfd, negotiate via ring_attach, and on success
// fill + PUBLISH the lane (active=1 last). Returns the live lane, or NULL on any failure (no lane / table
// full / server reject) -> the caller UDS-falls-back. This is the per-thread successor to P3's single
// shared attach; the body (memfd/mmap/cb fill/RPC) is unchanged -- only the destination is a per-thread
// lane instead of the g_* globals.
static gr_lane_t* gr_attach_lane(int tid) {
	gr_lane_t* L = gr_claim_lane(tid); // CAS-claims a free slot (active 0 -> 2 "claiming")
	if (!L) {
		g_stat_lanes_exhausted++; // D17: a claim that found the table full (reason C if this is ever >0)
		// table full: every lane is in use by another live thread. Fall back to UDS for this thread (never
		// share a lane -- that would break SPSC). Log once so an undersized GR_MAX_LANES is visible.
		if (!g_lanes_exhausted_logged) {
			g_lanes_exhausted_logged = 1;
#ifdef DARLING_RING_PHASE_PROF
			__simple_fprintf(2, "[dring] lane table exhausted (GR_MAX_LANES=%u) -- thread %d on UDS\n",
				(unsigned)GR_MAX_LANES, tid);
#endif
		}
		return 0;
	}

	// Lay out: [control block][c2s ring][s2c ring], each ring 64-aligned.
	uint64_t hdr = sizeof(dserver_ring_shm_t);
	uint64_t ring_span = sizeof(dserver_ring_t) + (uint64_t)GR_SLOT_COUNT * GR_SLOT_SIZE;
	uint64_t c2s_off = (hdr + 63u) & ~63ull;
	uint64_t s2c_off = (c2s_off + ring_span + 63u) & ~63ull;
	uint64_t total   = (s2c_off + ring_span + 63u) & ~63ull;

	// On ANY failure below we must RELEASE the claimed slot (active back to 0) so it isn't leaked.
	// memfd_create("dring", MFD_CLOEXEC=0x1)
	long memfd = LINUX_SYSCALL(__NR_memfd_create, "dring", 0x1u);
	if (memfd < 0) { __atomic_store_n(&L->active, 0u, __ATOMIC_RELEASE); return 0; }
	if (LINUX_SYSCALL(__NR_ftruncate, memfd, total) < 0) {
		LINUX_SYSCALL1(__NR_close, memfd);
		__atomic_store_n(&L->active, 0u, __ATOMIC_RELEASE); return 0;
	}

	// map RW shared
#ifdef __NR_mmap2
	void* map = (void*)LINUX_SYSCALL(__NR_mmap2, 0, total, 0x1 | 0x2 /*PROT_READ|WRITE*/, 0x1 /*MAP_SHARED*/, memfd, 0);
#else
	void* map = (void*)LINUX_SYSCALL(__NR_mmap, 0, total, 0x1 | 0x2, 0x1, memfd, 0);
#endif
	if ((unsigned long)map > (unsigned long)-4096) {
		LINUX_SYSCALL1(__NR_close, memfd);
		__atomic_store_n(&L->active, 0u, __ATOMIC_RELEASE); return 0;
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
	cb->guest_tid = (int32_t)tid; // server cross-checks vs SCM nsid; this lane is attached by THIS thread
	// perf #18 dar-1il.2 item 2: publish OUR compiled C2S opcode set as a hash. The server rejects
	// the ring (-> reject_opcode_set -> we use UDS for everything) if it doesn't match the set the
	// SERVER was built with -- so a guest/server build/version skew degrades cleanly to all-UDS
	// instead of stranding us on the first op the older side doesn't allowlist. Same FNV fold both
	// sides compute from the IDENTICAL DSERVER_RING_C2S_OPCODES macro.
	cb->c2s_opcode_hash = dserver_ring_c2s_opcode_hash();
	// perf #18 P4 wake-model words. The memfd is zero-filled, so these are already 0, but be
	// explicit: server_state starts SLEEPING_EPOLL (== 0) so we doorbell until the server first
	// publishes ACTIVE_POLLING; no guest is parked yet so s2c_waiters starts 0.
	cb->server_state = DSERVER_RING_SRV_SLEEPING_EPOLL;
	cb->s2c_waiters = 0;

	// negotiate over UDS: hand the memfd to the server. It validates + maps + returns the
	// wake eventfd (or a non-zero reject reason). This is a per-THREAD attach -- the server keys the
	// ring on this thread's nsid (RingAttach::processCall) and registers it in _ringThreads, so the
	// main-loop spin phase drains every attached thread's lane independently. (Server already per-thread.)
	uint32_t reject = 0;
	int wake_fd = -1;
	int rc = dserver_rpc_ring_attach((int)memfd, total, &reject, &wake_fd);

	// we no longer need the memfd ourselves (our mapping holds a reference).
	LINUX_SYSCALL1(__NR_close, memfd);

	if (rc != 0 || reject != dserver_ring_ok || wake_fd < 0) {
		LINUX_SYSCALL(__NR_munmap, map, total);
		if (wake_fd >= 0) LINUX_SYSCALL1(__NR_close, wake_fd);
		__atomic_store_n(&L->active, 0u, __ATOMIC_RELEASE); // release the claimed slot on reject
		return 0;
	}

	// dar-j7e7: the wake_fd arrived over SCM_RIGHTS with plain recvmsg flags (no MSG_CMSG_CLOEXEC), and the
	// server handed it out via ::dup() which STRIPS CLOEXEC -- so without this it leaks across execve into
	// every exec'd child (old code leaked 1 such fd; the per-thread table leaks up to GR_MAX_LANES). Make
	// the fd self-safe at the receiver: F_SETFD=2, FD_CLOEXEC=1 (fixed Linux ABI values, same raw-constant
	// idiom as memfd_create(MFD_CLOEXEC=0x1) above). Best-effort: a failure here doesn't invalidate the lane.
	LINUX_SYSCALL(__NR_fcntl, wake_fd, 2 /*F_SETFD*/, 1 /*FD_CLOEXEC*/);

	// INITIALIZE the lane fully, then PUBLISH active=1 LAST (the gate's INVARIANT 1). Bump the generation
	// on this (re)claim so a recycled TID landing on this slot can never match a prior epoch (INVARIANT 2).
	L->map = map;
	L->size = total;
	L->wake_fd = wake_fd;
	L->owner_tid = tid;
	L->seq = 1;
	L->state = 1;
	if (L->generation != 0) {
		g_stat_lanes_reclaimed++; // D17: this slot held a prior epoch -> it is being REUSED (not first use)
	}
	L->generation = L->generation + 1; // distinct epoch for this claim
	g_stat_lanes_acquired++; // D17: a successful per-thread attach in this process ("lanes acquired")
	__atomic_store_n(&L->active, 1u, __ATOMIC_RELEASE); // publish LAST: lane now usable + findable
	return L;
}

// Resolve THIS thread's lane: return its already-attached lane, or attach a fresh one, or NULL (no lane
// for this thread -> UDS fallback). This is the per-thread successor to the P3 single-owner gate.
static gr_lane_t* gr_lane_for_this_thread(void) {
	int tid = (int)LINUX_SYSCALL(__NR_gettid);
	gr_lane_t* L = gr_find_lane(tid);
	if (L) {
		return (L->state == 1) ? L : 0;
	}
	return gr_attach_lane(tid);
}

// Back-compat bool wrapper (the duplex selftest entry points still call this to gate themselves). True iff
// THIS thread has (or just acquired) a usable lane. The lane itself is resolved again by the caller via
// gr_lane_for_this_thread; this is only the "do I have a ring?" predicate.
bool __dserver_ring_try_attach(void) {
	return gr_lane_for_this_thread() != 0;
}

// perf #18 D17 (dar-1il.12): dump this process's per-thread lane stats to stderr, ONCE, on the clean exit
// path (called from sys_exit, mirroring __darling_rpc_sleep_dump). Default OFF: strict no-op unless the
// env DARLING_GUEST_LANE_STATS=1 is set (scanned libc-free from /proc/self/environ, same discipline as the
// other recon hatches -- set per-command on a warm server, NOT at boot, so daemons don't all dump). This
// surfaces the GUEST-side lane stats the server can't see directly: lanes_exhausted (>0 == reason C),
// lanes_reclaimed (slot reuse), and a live snapshot of how many lanes this process actually holds.
static int g_lane_stats_dumped = 0;
void __dserver_ring_lane_stats_dump(void) {
	if (g_lane_stats_dumped) {
		return;
	}
	g_lane_stats_dumped = 1;
	// env gate (libc-free scan of /proc/self/environ for DARLING_GUEST_LANE_STATS=1).
	long efd = LINUX_SYSCALL(__NR_open, "/proc/self/environ", 0 /*O_RDONLY*/, 0);
	if (efd < 0) {
		return;
	}
	static const char key[] = "DARLING_GUEST_LANE_STATS=1";
	const __SIZE_TYPE__ keylen = sizeof(key) - 1;
	char buf[4096];
	int found = 0;
	for (;;) {
		long n = LINUX_SYSCALL(__NR_read, efd, buf, sizeof(buf));
		if (n <= 0) break;
		__SIZE_TYPE__ start = 0;
		for (__SIZE_TYPE__ i = 0; i < (__SIZE_TYPE__)n; ++i) {
			if (buf[i] == '\0') {
				if (i - start == keylen) {
					int eq = 1;
					for (__SIZE_TYPE__ k = 0; k < keylen; ++k) {
						if (buf[start + k] != key[k]) { eq = 0; break; }
					}
					if (eq) found = 1;
				}
				start = i + 1;
			}
		}
		if (found || (__SIZE_TYPE__)n < (long)sizeof(buf)) break;
	}
	LINUX_SYSCALL1(__NR_close, efd);
	if (!found) {
		return; // env not set -> strict no-op (every normal process)
	}
	// count lanes this process currently holds (active==1) for max-lanes context.
	unsigned held = 0;
	for (uint32_t i = 0; i < GR_MAX_LANES; ++i) {
		if (__atomic_load_n(&g_lanes[i].active, __ATOMIC_RELAXED) == 1) ++held;
	}
	__simple_fprintf(2, "[dring-lane-stats] pid=%d acquired=%llu exhausted=%llu reclaimed=%llu held_now=%u max=%u\n",
		(int)LINUX_SYSCALL(__NR_getpid),
		(unsigned long long)g_stat_lanes_acquired,
		(unsigned long long)g_stat_lanes_exhausted,
		(unsigned long long)g_stat_lanes_reclaimed,
		held, (unsigned)GR_MAX_LANES);
}

// Wake the server -- CONDITIONALLY (perf #18 P4). We just published a request on lane L. The server only
// needs a doorbell if it is not actively polling its rings; while it spins (ACTIVE_POLLING) it
// will see our new c2s tail on its own, so the eventfd write is pure overhead and we skip it.
// dserver_ring_guest_should_doorbell() reads the server-published state with acquire ordering;
// a stale read at worst costs one redundant write, never a missed wake (an old/0 value ==
// SLEEPING_EPOLL == "doorbell", the safe direction). Each lane has its OWN wake fd (per-thread).
static void gr_wake_server(gr_lane_t* L) {
	if (!dserver_ring_guest_should_doorbell(gr_cb(L))) {
		return; // server is draining rings; it'll pick up our request without a syscall
	}
	uint64_t one = 1;
	LINUX_SYSCALL(__NR_write, L->wake_fd, &one, sizeof(one));
}

// Wait for a reply on s2c after the request has been published. Once published, the server may
// already have performed the operation, so give-up is a committed-or-unknown state, not a UDS retry
// signal. Only pre-publish failures may fall back to UDS.
//
// perf #18 P4: the hot path is the spin -- if the server replies within DARLING_GUEST_RECVSPIN
// iterations we return without touching the kernel AND without ever advertising ourselves as a
// waiter, so the server's conditional FUTEX_WAKE is a no-op too (zero syscalls round-trip). Only
// when we fall through to the slow path do we set s2c_waiters before parking, so the server knows
// to wake us; we clear it on the way out. The bit is set BEFORE the pre-sleep ring recheck, so the
// server can never publish-then-skip-wake while we're committed to sleeping (it reads the bit
// after publishing; if it sees 0 we hadn't slept yet and are still spinning the recheck).
static gr_wait_result_t gr_wait_reply(gr_lane_t* L) {
	dserver_ring_t* s2c = gr_s2c(L);
	for (int i = 0; i < (DARLING_GUEST_RECVSPIN); ++i) {
		dserver_ring_slot_t* rep = dserver_ring_consumer_begin(s2c, GR_SLOT_SIZE, GR_SLOT_COUNT);
		if (rep) return (gr_wait_result_t){ GR_WAIT_COMPLETED, rep };
		gr_relax();
	}
	// Slow path: advertise ourselves as a parked waiter so the server's conditional FUTEX_WAKE
	// fires, then sleep on the futex until it bumps the word. Re-check after each wake.
	uint32_t* word = &gr_cb(L)->s2c_futex;
	uint32_t* waiters = &gr_cb(L)->s2c_waiters;
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
	if (result) {
		return (gr_wait_result_t){ GR_WAIT_COMPLETED, result };
	}
	return (gr_wait_result_t){ GR_WAIT_COMMITTED_UNKNOWN, 0 };
}

// Shared fast path for the no-arg, single-uint32-port-reply traps (task_self_trap,
// mach_reply_port). Publishes an empty-body request for `callnum`, wakes the server, waits for
// the reply, and validates seq+callnum+length before copying out the port. Returns 0 + writes
// *out_port on success; returns negative only on a pre-publish miss where UDS fallback is safe.
// After publish, timeout/bad-reply is committed-unknown and returns KERN_FAILURE without retrying.
// The reply convention ({reply_hdr.code, uint32 port}) is identical for both calls, so one helper covers them.
static int gr_port_trap(uint32_t callnum, uint32_t* out_port) {
	gr_lane_t* L = gr_lane_for_this_thread();
	if (!L) {
		return -1; // no ring for this thread -> UDS fallback
	}

#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t0 = gr_rdtsc();
#endif
	dserver_ring_t* c2s = gr_c2s(L);
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -1; // ring full -> UDS fallback
	}
	uint32_t seq = L->seq++;
	req->callnum = callnum;
	req->seq = seq;
	req->length = 0;
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	dserver_ring_producer_publish(c2s);

	gr_wake_server(L);

#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t1 = gr_rdtsc(); // submit done
#endif
	gr_wait_result_t wait = gr_wait_reply(L);
	if (wait.state == GR_WAIT_COMMITTED_UNKNOWN) {
		return KERN_FAILURE; // published: do NOT retry over UDS
	}
	dserver_ring_slot_t* rep = wait.slot;
#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t2 = gr_rdtsc(); // reply observed (roundtrip done)
#endif

	// Validate the reply belongs to our request before trusting it.
	int rc = KERN_FAILURE; // bad/mismatched reply after publish: fail closed, do NOT UDS-retry
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
	dserver_ring_consumer_advance(gr_s2c(L));
#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t3 = gr_rdtsc(); // observe (validate + copy out) done
	gr_ph_submit  += (_t1 - _t0);
	gr_ph_round   += (_t2 - _t1);
	gr_ph_observe += (_t3 - _t2);
	gr_ph_total   += (_t3 - _t0);
	++gr_ph_n;
	gr_phase_maybe_dump();
#endif
	return rc;
}

int __dserver_ring_task_self_trap(uint32_t* out_port) {
	return gr_port_trap((uint32_t)dserver_callnum_task_self_trap, out_port);
}

// perf #18 D10 (dar-1il.5): thread_self_trap + host_self_trap -- the remaining pure-mint self-trap
// family. Byte-identical transport shape to task_self_trap (empty request, single uint32 port reply),
// so they reuse gr_port_trap verbatim. Each routes over the ring iff it is in DSERVER_RING_C2S_OPCODES
// (the shared allowlist the server keys off too); on any transport miss the caller UDS-falls-back.
int __dserver_ring_thread_self_trap(uint32_t* out_port) {
	return gr_port_trap((uint32_t)dserver_callnum_thread_self_trap, out_port);
}

int __dserver_ring_host_self_trap(uint32_t* out_port) {
	return gr_port_trap((uint32_t)dserver_callnum_host_self_trap, out_port);
}

int __dserver_ring_mach_reply_port(uint32_t* out_port) {
	return gr_port_trap((uint32_t)dserver_callnum_mach_reply_port, out_port);
}

// perf #18 P5 (dar-1il): generic fast path for a small-inline-body op whose reply is HEADER-ONLY
// (the meaningful result is the reply hdr's `code` = a kern_return_t, no port/body). Unlike
// gr_port_trap (empty request, port reply), this publishes `bodylen` bytes of request body inline
// in the slot and copies NOTHING out of the reply but the code. Used by mach_port_mod_refs.
//
// Contract mirrors gr_port_trap's transport semantics but splits the result from the
// fall-back signal: returns 0 on a VALID ring round-trip and writes *out_code (the kern_return_t,
// which the caller must use verbatim -- it may be KERN_INVALID_NAME etc.); returns -1 on any
// transport miss BEFORE publish (no ring / ring full), in which case the caller MUST UDS-fall-back.
// Once published, timeout/bad-reply is committed-unknown: return 0 with *out_code=KERN_FAILURE so
// the caller observes failure without re-running the operation over UDS.
// This separation matters because a kern_return_t can be any value and must never be confused
// with the "-1 = retry on UDS" sentinel (gr_port_trap could conflate them only because that op's
// code is always 0).
static int gr_body_trap(uint32_t callnum, const void* body, uint32_t bodylen, int* out_code) {
	gr_lane_t* L = gr_lane_for_this_thread();
	if (!L) {
		return -1; // no ring for this thread -> UDS fallback
	}

	uint32_t inlineCap = GR_SLOT_SIZE - (uint32_t)sizeof(dserver_ring_slot_t);
	if (bodylen > inlineCap) {
		return -1; // body won't fit the slot -> UDS fallback (shouldn't happen for our small ops)
	}

#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t0 = gr_rdtsc();
#endif
	dserver_ring_t* c2s = gr_c2s(L);
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -1; // ring full -> UDS fallback
	}
	uint32_t seq = L->seq++;
	req->callnum = callnum;
	req->seq = seq;
	req->length = bodylen;
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	if (bodylen > 0) {
		memcpy((char*)req + sizeof(dserver_ring_slot_t), body, bodylen);
	}
	dserver_ring_producer_publish(c2s);

	gr_wake_server(L);

#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t1 = gr_rdtsc(); // submit done
#endif
	gr_wait_result_t wait = gr_wait_reply(L);
	if (wait.state == GR_WAIT_COMMITTED_UNKNOWN) {
		if (out_code) *out_code = KERN_FAILURE;
		return 0; // published: do NOT retry over UDS
	}
	dserver_ring_slot_t* rep = wait.slot;
#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t2 = gr_rdtsc(); // reply observed (roundtrip done)
#endif

	// Validate the reply belongs to our request before trusting it. The reply is header-only:
	// length must be exactly the reply hdr (no body), and code is the kern_return_t.
	int rc = 0;
	if (out_code) *out_code = KERN_FAILURE; // bad/mismatched reply after publish: no UDS retry
	if (rep->seq == seq && rep->callnum == callnum) {
		if (rep->length >= sizeof(dserver_ring_reply_hdr_t) && rep->length <= inlineCap) {
			char* payload = (char*)rep + sizeof(dserver_ring_slot_t);
			dserver_ring_reply_hdr_t* rh = (dserver_ring_reply_hdr_t*)payload;
			if (out_code) *out_code = rh->code;
			rc = 0; // valid ring round-trip
		}
	}
	dserver_ring_consumer_advance(gr_s2c(L));
#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t3 = gr_rdtsc(); // observe done
	gr_ph_submit  += (_t1 - _t0);
	gr_ph_round   += (_t2 - _t1);
	gr_ph_observe += (_t3 - _t2);
	gr_ph_total   += (_t3 - _t0);
	++gr_ph_n;
	gr_phase_maybe_dump();
#endif
	return rc;
}

// perf #18 D11 (dar-1il.6): generic fast path for a CLOSED op with a small inline request body AND a
// small inline reply BODY (not just the kern_return code). Unlike gr_body_trap (header-only reply),
// this also copies `replylen` bytes of reply body out of the slot into `reply_out` -- the over-the-wire
// reply body is byte-identical to the UDS dserver_reply_<op>_t struct, because the server publishes
// everything after the reply hdr onto the ring (_publishReplyToRingLocked). The result code is split
// from the transport-miss sentinel exactly like gr_body_trap: returns 0 on a VALID ring round-trip and
// writes *out_code (the kern_return_t, verbatim) + reply_out; returns -1 on ANY transport miss (no ring
// / full) in which case the caller MUST UDS-fall-back. Once published, timeout/bad-reply/shape
// mismatch is committed-unknown: return 0 with *out_code=KERN_FAILURE so the caller observes failure
// without re-running the operation over UDS. `replylen` is the EXACT expected reply-body size (0 for a
// header-only reply -- then reply_out may be NULL); the reply is accepted only if rep->length ==
// sizeof(reply_hdr) + replylen.
static int gr_full_trap(uint32_t callnum, const void* body, uint32_t bodylen,
                        void* reply_out, uint32_t replylen, int* out_code) {
	gr_lane_t* L = gr_lane_for_this_thread();
	if (!L) {
		return -1; // no ring for this thread -> UDS fallback
	}

	uint32_t inlineCap = GR_SLOT_SIZE - (uint32_t)sizeof(dserver_ring_slot_t);
	if (bodylen > inlineCap || (uint32_t)sizeof(dserver_ring_reply_hdr_t) + replylen > inlineCap) {
		return -1; // body/reply won't fit the slot -> UDS fallback (shouldn't happen for our small ops)
	}

#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t0 = gr_rdtsc();
#endif
	dserver_ring_t* c2s = gr_c2s(L);
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -1; // ring full -> UDS fallback
	}
	uint32_t seq = L->seq++;
	req->callnum = callnum;
	req->seq = seq;
	req->length = bodylen;
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	if (bodylen > 0) {
		memcpy((char*)req + sizeof(dserver_ring_slot_t), body, bodylen);
	}
	dserver_ring_producer_publish(c2s);

	gr_wake_server(L);

#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t1 = gr_rdtsc(); // submit done
#endif
	gr_wait_result_t wait = gr_wait_reply(L);
	if (wait.state == GR_WAIT_COMMITTED_UNKNOWN) {
		if (out_code) *out_code = KERN_FAILURE;
		return 0; // published: do NOT retry over UDS
	}
	dserver_ring_slot_t* rep = wait.slot;
#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t2 = gr_rdtsc(); // reply observed (roundtrip done)
#endif

	// Validate the reply belongs to our request before trusting it. The reply must be EXACTLY
	// {reply_hdr, replylen-byte body}; a different length means the server replied with a different
	// shape (error/wrong op) -> treat as a transport miss so the caller UDS-falls-back and re-runs.
	int rc = 0;
	if (out_code) *out_code = KERN_FAILURE; // bad/mismatched reply after publish: no UDS retry
	if (rep->seq == seq && rep->callnum == callnum) {
		if (rep->length == (uint32_t)sizeof(dserver_ring_reply_hdr_t) + replylen && rep->length <= inlineCap) {
			char* payload = (char*)rep + sizeof(dserver_ring_slot_t);
			dserver_ring_reply_hdr_t* rh = (dserver_ring_reply_hdr_t*)payload;
			if (out_code) *out_code = rh->code;
			if (replylen > 0 && reply_out) {
				memcpy(reply_out, payload + sizeof(dserver_ring_reply_hdr_t), replylen);
			}
			rc = 0; // valid ring round-trip
		}
	}
	dserver_ring_consumer_advance(gr_s2c(L));
#ifdef DARLING_RING_PHASE_PROF
	unsigned long _t3 = gr_rdtsc(); // observe done
	gr_ph_submit  += (_t1 - _t0);
	gr_ph_round   += (_t2 - _t1);
	gr_ph_observe += (_t3 - _t2);
	gr_ph_total   += (_t3 - _t0);
	++gr_ph_n;
	gr_phase_maybe_dump();
#endif
	return rc;
}

// perf #18 D11 (dar-1il.6): the 5 bulk Lane-1 op wrappers. Each mirrors the matching UDS
// dserver_rpc_<op> contract: returns 0 + writes the out-params on a valid ring round-trip; returns
// negative on any transport miss -> caller MUST UDS-fall-back. The request/reply body layouts below
// are byte-identical to the generated dserver_call_<op>_t / dserver_reply_<op>_t structs (verified
// against the generated rpc.h), so the server rebuilds {callhdr, body} and dispatches via the SAME
// generic Call path / dtape primitive as over UDS -- behavior is byte-identical, only the transport
// differs. None is destroy-capable or caller-S2C (canon rules 1-2 hold); they ride the GENERIC fiber
// doWork() path (Tier-1, NOT the no-fiber inline fast path).

int __dserver_ring_uidgid(int32_t new_uid, int32_t new_gid, int32_t* out_old_uid, int32_t* out_old_gid, int* out_code) {
	// dserver_call_uidgid_t { int32_t new_uid; int32_t new_gid; } -> dserver_reply_uidgid_t { int32_t old_uid; int32_t old_gid; }
	struct { int32_t new_uid; int32_t new_gid; } body = { new_uid, new_gid };
	struct { int32_t old_uid; int32_t old_gid; } reply;
	int rc = gr_full_trap((uint32_t)dserver_callnum_uidgid, &body, (uint32_t)sizeof(body),
	                      &reply, (uint32_t)sizeof(reply), out_code);
	if (rc == 0) {
		if (out_old_uid) *out_old_uid = reply.old_uid;
		if (out_old_gid) *out_old_gid = reply.old_gid;
	}
	return rc;
}

int __dserver_ring_set_thread_handles(uint64_t pthread_handle, uint64_t dispatch_qaddr, int* out_code) {
	// dserver_call_set_thread_handles_t { uint64_t pthread_handle aligned(8); uint64_t dispatch_qaddr aligned(8); } -> header-only reply
	struct {
		uint64_t pthread_handle __attribute__((aligned(8)));
		uint64_t dispatch_qaddr __attribute__((aligned(8)));
	} body = { pthread_handle, dispatch_qaddr };
	return gr_full_trap((uint32_t)dserver_callnum_set_thread_handles, &body, (uint32_t)sizeof(body),
	                    (void*)0, 0, out_code);
}

int __dserver_ring_started_suspended(bool* out_suspended, int* out_code) {
	// empty request -> dserver_reply_started_suspended_t { bool suspended; }
	struct { bool suspended; } reply;
	int rc = gr_full_trap((uint32_t)dserver_callnum_started_suspended, (void*)0, 0,
	                      &reply, (uint32_t)sizeof(reply), out_code);
	if (rc == 0 && out_suspended) *out_suspended = reply.suspended;
	return rc;
}

int __dserver_ring_get_tracer(int32_t* out_tracer, int* out_code) {
	// empty request -> dserver_reply_get_tracer_t { int32_t tracer; }
	struct { int32_t tracer; } reply;
	int rc = gr_full_trap((uint32_t)dserver_callnum_get_tracer, (void*)0, 0,
	                      &reply, (uint32_t)sizeof(reply), out_code);
	if (rc == 0 && out_tracer) *out_tracer = reply.tracer;
	return rc;
}

int __dserver_ring_task_is_64_bit(int32_t id, bool* out_is_64_bit, int* out_code) {
	// dserver_call_task_is_64_bit_t { int32_t id; } -> dserver_reply_task_is_64_bit_t { bool is_64_bit; }
	struct { int32_t id; } body = { id };
	struct { bool is_64_bit; } reply;
	int rc = gr_full_trap((uint32_t)dserver_callnum_task_is_64_bit, &body, (uint32_t)sizeof(body),
	                      &reply, (uint32_t)sizeof(reply), out_code);
	if (rc == 0 && out_is_64_bit) *out_is_64_bit = reply.is_64_bit;
	return rc;
}

// perf #18 D13 (dar-1il.8): the two path-op wrappers. Despite the char*/path UDS signature, the path
// bytes do NOT travel in the RPC payload -- `buffer` is the GUEST virtual address into which the server
// writes the path via process_vm_writev (writeMemory) on the guest's /proc/mem, exactly as over UDS.
// So the ring request body is the FIXED 16B { uint64_t buffer; uint64_t buffer_size; } (byte-identical
// to dserver_call_<op>_t) and the reply is the 8B { uint64_t length; } (byte-identical to
// dserver_reply_<op>_t) -- no arena, no variable payload. /proc/mem access is server-side and needs no
// caller-S2C, and the op is a pure read of server config (no destroy), so all 5 canon rules hold. Each
// routes over the ring iff it is in DSERVER_RING_C2S_OPCODES; on any transport miss the caller MUST
// UDS-fall-back. (set_executable_path is NOT migrated: pre-attach mldr-only + NO_REPLY.)

int __dserver_ring_vchroot_path(uint64_t buffer, uint64_t buffer_size, uint64_t* out_length, int* out_code) {
	// dserver_call_vchroot_path_t { uint64_t buffer aligned(8); uint64_t buffer_size aligned(8); }
	//   -> dserver_reply_vchroot_path_t { uint64_t length aligned(8); }
	struct {
		uint64_t buffer __attribute__((aligned(8)));
		uint64_t buffer_size __attribute__((aligned(8)));
	} body = { buffer, buffer_size };
	struct { uint64_t length __attribute__((aligned(8))); } reply;
	int rc = gr_full_trap((uint32_t)dserver_callnum_vchroot_path, &body, (uint32_t)sizeof(body),
	                      &reply, (uint32_t)sizeof(reply), out_code);
	if (rc == 0 && out_length) *out_length = reply.length;
	return rc;
}

int __dserver_ring_mldr_path(uint64_t buffer, uint64_t buffer_size, uint64_t* out_length, int* out_code) {
	// dserver_call_mldr_path_t { uint64_t buffer aligned(8); uint64_t buffer_size aligned(8); }
	//   -> dserver_reply_mldr_path_t { uint64_t length aligned(8); }
	struct {
		uint64_t buffer __attribute__((aligned(8)));
		uint64_t buffer_size __attribute__((aligned(8)));
	} body = { buffer, buffer_size };
	struct { uint64_t length __attribute__((aligned(8))); } reply;
	int rc = gr_full_trap((uint32_t)dserver_callnum_mldr_path, &body, (uint32_t)sizeof(body),
	                      &reply, (uint32_t)sizeof(reply), out_code);
	if (rc == 0 && out_length) *out_length = reply.length;
	return rc;
}

// perf #18 P5-bulk audit (dar-1il.2): mach_port_mod_refs has NO ring helper -- it was removed from
// DSERVER_RING_C2S_OPCODES because it is destroy-capable (negative-delta last-ref destroy -> vm
// munmap S2C upcall to a caller parked on the ring -> deadlock; same class as mach_port_deallocate).
// It routes UDS-only (see mach_traps.c _kernelrpc_mach_port_mod_refs_trap_impl).

// perf #18 P5-bulk (dar-1il.1): two more port/right bookkeeping ops ride the ring. Both are a
// Tier-1 shape: a small inline request body + a HEADER-ONLY reply (the result is the kern_return_t;
// allocate also copies the name out via the existing guest-memory write the generic Call path does).
// Each body layout below is byte-identical to the generated dserver_call_<name>_t, so the server
// rebuilds {callhdr, body} and dispatches via callFromMessage -> the identical dtape primitive as
// over UDS. They ride the GENERIC fiber doWork() path on the server (NOT the no-fiber inline path,
// which off-fiber-corrupts the thread stack; see call.cpp ringFastPathEligible). Each routes over
// the ring iff it is in DSERVER_RING_C2S_OPCODES (rpc-supplement.h), the single shared allowlist the
// server keys off too. (allocate/insert_right are kept; mach_port_deallocate's helper below is dead
// -- deallocate also reverted to UDS-only in dar-1il.1 -- and left only to minimize that diff.)

int __dserver_ring_mach_port_deallocate(uint32_t target, uint32_t name, int* out_code) {
	// dserver_call_mach_port_deallocate_t { uint32_t target; uint32_t name; }
	struct {
		uint32_t target;
		uint32_t name;
	} body = { target, name };
	return gr_body_trap((uint32_t)dserver_callnum_mach_port_deallocate, &body, (uint32_t)sizeof(body), out_code);
}

int __dserver_ring_mach_port_allocate(uint32_t target, int32_t right, uint64_t name_ptr, int* out_code) {
	// dserver_call_mach_port_allocate_t { uint32_t target; int32_t right; uint64_t name aligned(8); }
	// `name` is the GUEST virtual address the kernel writes the allocated port name into; we send the
	// pointer value verbatim and the server (generic Call path) performs the same guest-memory write
	// it does over UDS. The reply is header-only (the kern_return_t). The 8-byte alignment of the
	// uint64_t matches the generated struct's __attribute__((aligned(8))) (offset 8, size 16).
	struct {
		uint32_t target;
		int32_t  right;
		uint64_t name __attribute__((aligned(8)));
	} body = { target, right, name_ptr };
	return gr_body_trap((uint32_t)dserver_callnum_mach_port_allocate, &body, (uint32_t)sizeof(body), out_code);
}

// === perf #18 P8 D3 (dar-1il.3.1.1): DUPLEX-lane wait-pump + synthetic selftest =====================
//
// The duplex lane lets the server deliver an S2C upcall to a caller that is PARKED on the ring (not in
// recvmsg) -- the deadlock class that kept deallocate/mod_refs on UDS. The minimal D3 proof drives ONE
// synthetic ECHO upcall end-to-end through the REAL dylib: the guest publishes a sentinel parent
// request, then runs a wait-pump that, while waiting for the parent's final reply, ALSO services the
// S2C upcall mailbox -- handling each upcall ON THIS (caller) thread and replying with matching
// correlation ids. NO real op rides this yet (deallocate is Phase E, blocked on D3 GREEN).
//
// Wake discipline mirrors gr_wait_reply (the proven Lane-1 model): bounded spin watching BOTH the s2c
// reply ring AND the duplex upcall mailbox, then a FUTEX_WAIT on s2c_futex with the waiter bit set
// before the pre-sleep recheck (no lost wake). After publishing an upcall REPLY we doorbell the server
// (it may be epoll-sleeping; the reply is server-inbound work just like a request is), conditionally,
// exactly like gr_wake_server.

// Handle ONE pending duplex S2C upcall on THIS thread, if present. Returns 1 if it handled one (and
// published the correlated reply + doorbelled the server), 0 if none was pending. The ECHO shape is
// the only one the minimal protocol supports; an unknown shape is replied with a nonzero status so the
// server fails the parent rather than hanging.
static int gr_duplex_pump_once(gr_lane_t* L) {
#ifdef DUPLEX_RED_NO_GUEST_PUMP
	(void)L;
	// RED arm for the D3 real-dylib gate: the guest NEVER services the S2C upcall. The parked caller
	// then sleeps through the upcall forever -> the selftest must FAIL/timeout (the parent reply never
	// comes) AND the server must NOT wedge (other clients keep making progress). Proves the gate
	// actually exercises the guest pump + the server's bounded, scoped wait.
	return 0;
#else
	dserver_ring_shm_t* cb = gr_cb(L);
	if (!dserver_ring_duplex_upcall_available(cb)) {
		return 0;
	}
	uint32_t op     = cb->duplex_upcall_op;
	uint32_t parent = cb->duplex_upcall_parent;
	uint32_t uid    = cb->duplex_upcall_id;
	if (op == DSERVER_RING_DUPLEX_UPCALL_MUNMAP) {
		// perf #18 P8 D4: the REAL vm-munmap S2C upcall (mach_port_deallocate of a mapped-region-backed
		// port drives this). Run the SAME munmap(2) the UDS recvmsg S2C path runs (dserver-rpc-defs.h
		// dserver_s2c_msgnum_munmap) ON THIS (caller) thread, so the side effect is byte-identical to UDS
		// -- only the transport differs. The reply carries the kernel return_value + errno verbatim.
		uint64_t addr = cb->duplex_upcall_addr;
		uint64_t len  = cb->duplex_upcall_len;
		long call_ret = LINUX_SYSCALL2(__NR_munmap, addr, len);
		int32_t return_value, errno_result;
		if (call_ret < 0) {
			return_value = -1;
			errno_result = (int32_t)(-call_ret);
		} else {
			return_value = (int32_t)call_ret;
			errno_result = 0;
		}
		dserver_ring_duplex_publish_munmap_reply(cb, parent, uid, return_value, errno_result);
		gr_wake_server(L);
		return 1;
	}
	uint32_t a      = cb->duplex_upcall_arg;
	int32_t  status = 0;
	uint32_t result = 0;
	if (op == DSERVER_RING_DUPLEX_UPCALL_ECHO) {
		result = dserver_ring_duplex_echo_transform(a);
	} else {
		status = -1; // unsupported shape -> the server fails the parent
	}
	// publish the reply (this consumes the upcall + advertises the reply, both release-stores).
	dserver_ring_duplex_publish_reply(cb, parent, uid, status, result);
	// the reply is server-inbound work; doorbell conditionally so an epoll-sleeping server drains it.
	gr_wake_server(L);
	return 1;
#endif // DUPLEX_RED_NO_GUEST_PUMP
}

// Wait for the sentinel parent's FINAL reply on the s2c ring while pumping duplex S2C upcalls. This is
// gr_wait_reply's structure with the upcall pump interleaved into BOTH the spin and the parked loop, so
// a parked caller can never sleep through an upcall (the duplex wake model, ring_duplex_wake_gate_test).
// Give-up after publish is committed-unknown, not a UDS retry signal.
static gr_wait_result_t gr_duplex_wait_reply(gr_lane_t* L) {
	dserver_ring_t* s2c = gr_s2c(L);
	for (int i = 0; i < (DARLING_GUEST_RECVSPIN); ++i) {
		// pump first: an upcall must be serviced before the parent reply can ever arrive.
		while (gr_duplex_pump_once(L)) { /* drain all currently-pending upcalls */ }
		dserver_ring_slot_t* rep = dserver_ring_consumer_begin(s2c, GR_SLOT_SIZE, GR_SLOT_COUNT);
		if (rep) return (gr_wait_result_t){ GR_WAIT_COMPLETED, rep };
		gr_relax();
	}
	// Slow path: park on the s2c futex. Set the waiter bit BEFORE the recheck so the server's
	// conditional FUTEX_WAKE fires; re-pump + re-check the ring after every wake.
	//
	// CRITICAL (the lane's whole reason to exist): the FUTEX_WAIT is BOUNDED (a per-wait timespec),
	// NOT an indefinite block. The duplex lane exists to keep a caller-S2C op from DEADLOCKING a parked
	// guest; if an upcall is somehow never serviced (a bug, a torn-down server, or -- in the D3 RED arm
	// -- a deliberately disabled pump), an UNBOUNDED FUTEX_WAIT would re-introduce exactly the wedge we
	// are trying to prevent (and, since the selftest can run in launchd, would wedge boot). So we cap
	// the total parked time and give up -> committed-unknown. The cap is generous (a real reply lands
	// in microseconds) so it never trips in GREEN.
	uint32_t* word = &gr_cb(L)->s2c_futex;
	uint32_t* waiters = &gr_cb(L)->s2c_waiters;
	__atomic_store_n(waiters, 1u, __ATOMIC_RELEASE);
	dserver_ring_slot_t* result = 0;
	// 50ms per FUTEX_WAIT * up to 60 rounds = ~3s total worst-case bound before giving up.
	struct { long tv_sec; long tv_nsec; } ts = { 0, 50L * 1000L * 1000L };
	for (int guard = 0; guard < 60; ++guard) {
		uint32_t observed = __atomic_load_n(word, __ATOMIC_ACQUIRE);
		// pump BEFORE sleeping: an upcall published just before we parked must be drained, not slept
		// through. The waiter bit is already set, so any reply/upcall the server publishes bumps the
		// futex word -> our FUTEX_WAIT returns EAGAIN and we re-pump. (duplex wake model: guest pump.)
#ifndef D6_RED_NO_PUMP
		while (gr_duplex_pump_once(L)) { /* drain */ }
#endif
		// D6_RED_NO_PUMP arm: the guest NEVER pumps the S2C upcall. The server's caller-S2C munmap is then
		// never serviced -> the parent op never completes -> the wait MUST bound out (return NULL) without
		// wedging (proving the cure is real: pumping is what completes it, and the absence is bounded-safe).
		dserver_ring_slot_t* rep = dserver_ring_consumer_begin(s2c, GR_SLOT_SIZE, GR_SLOT_COUNT);
		if (rep) { result = rep; break; }
		long r = LINUX_SYSCALL(__NR_futex, word, GR_FUTEX_WAIT, observed, &ts, 0, 0);
		(void)r; // EAGAIN (word changed) / EINTR / ETIMEDOUT -> re-loop, re-pump, re-check; on a
		         // persistent no-reply we exhaust the guard and return committed-unknown (bounded, no wedge).
	}
	__atomic_store_n(waiters, 0u, __ATOMIC_RELEASE);
	if (result) {
		return (gr_wait_result_t){ GR_WAIT_COMPLETED, result };
	}
	return (gr_wait_result_t){ GR_WAIT_COMMITTED_UNKNOWN, 0 };
}

// The synthetic selftest entry. Advertises the SELFTEST duplex capability, publishes the sentinel
// parent request carrying `arg`, runs the duplex wait-pump, and on success writes the final echo
// result to *out_result and returns 0. Returns negative on any transport miss/error; this selftest
// has no UDS retry path, so committed-unknown is only reported as a stable failure code.
// Drives the REAL transport: real ring publish, real server _drainDuplexReply, real guest pump.
int __dserver_ring_duplex_selftest(uint32_t arg, uint32_t* out_result) {
	gr_lane_t* L = gr_lane_for_this_thread();
	if (!L) {
		return -1; // no ring for this thread
	}
	// advertise that we can pump the SELFTEST upcall shape; the server's guard requires this cap.
	// (release so the server sees it before it can observe our sentinel request.)
	__atomic_store_n(&gr_cb(L)->duplex_caps, DSERVER_RING_DUPLEX_CAP_SELFTEST, __ATOMIC_RELEASE);

	dserver_ring_t* c2s = gr_c2s(L);
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -2; // ring full
	}
	uint32_t seq = L->seq++;
	req->callnum = DSERVER_RING_DUPLEX_SELFTEST_CALLNUM;
	req->seq = seq;
	req->length = (uint32_t)sizeof(uint32_t);
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	memcpy((char*)req + sizeof(dserver_ring_slot_t), &arg, sizeof(arg));
	dserver_ring_producer_publish(c2s);
	gr_wake_server(L);

	gr_wait_result_t wait = gr_duplex_wait_reply(L);
	if (wait.state == GR_WAIT_COMMITTED_UNKNOWN) {
		return -3; // published but gave up waiting for the final reply
	}
	dserver_ring_slot_t* rep = wait.slot;
	int rc = -4;
	if (rep->seq == seq && rep->callnum == DSERVER_RING_DUPLEX_SELFTEST_CALLNUM) {
		uint32_t inlineCap = GR_SLOT_SIZE - (uint32_t)sizeof(dserver_ring_slot_t);
		if (rep->length >= sizeof(dserver_ring_reply_hdr_t) && rep->length <= inlineCap) {
			char* payload = (char*)rep + sizeof(dserver_ring_slot_t);
			dserver_ring_reply_hdr_t* rh = (dserver_ring_reply_hdr_t*)payload;
			if (rh->code != 0) {
				rc = -5; // server reported the parent failed (guard declined / mis-correlation)
			} else if (rep->length >= sizeof(dserver_ring_reply_hdr_t) + sizeof(uint32_t)) {
				uint32_t result;
				memcpy(&result, payload + sizeof(dserver_ring_reply_hdr_t), sizeof(result));
				if (out_result) *out_result = result;
				rc = 0;
			}
		}
	}
	dserver_ring_consumer_advance(gr_s2c(L));
	return rc;
}

// The selftest trigger is a MARKER FILE, not an env var. A marker scopes the selftest to the test run
// (absent on a normal boot -> strict no-op) without the env-inheritance hazard of disrupting a specific
// daemon. The TRIGGER is the env var DARLING_GUEST_DUPLEX_SELFTEST=1, scanned libc-free from
// /proc/self/environ. THE DISCIPLINE THAT MAKES IT SAFE: the harness sets the env ONLY on the
// per-command `darling shell` invocation against an ALREADY-WARM server -- it does NOT set it at boot.
// So the long-lived daemons (launchd, shellspawn) were started without it and never run the selftest;
// only the explicitly-targeted leaf process inherits the env and runs it. (An env set at BOOT time IS
// inherited by shellspawn and wedges it -- do not do that.) Belt-and-suspenders: we also skip guest
// pid 1, and the per-process duplex wait is BOUNDED so even an unexpected daemon hit cannot wedge.
static int gr_duplex_selftest_enabled(void) {
	long efd = LINUX_SYSCALL(__NR_open, "/proc/self/environ", 0 /*O_RDONLY*/, 0);
	if (efd < 0) {
		return 0;
	}
	static const char key[] = "DARLING_GUEST_DUPLEX_SELFTEST=1";
	const __SIZE_TYPE__ keylen = sizeof(key) - 1;
	char buf[4096];
	int found = 0;
	for (;;) {
		long n = LINUX_SYSCALL(__NR_read, efd, buf, sizeof(buf));
		if (n <= 0) break;
		__SIZE_TYPE__ start = 0;
		for (__SIZE_TYPE__ i = 0; i < (__SIZE_TYPE__)n; ++i) {
			if (buf[i] == '\0') {
				if (i - start == keylen) {
					int eq = 1;
					for (__SIZE_TYPE__ k = 0; k < keylen; ++k) {
						if (buf[start + k] != key[k]) { eq = 0; break; }
					}
					if (eq) found = 1;
				}
				start = i + 1;
			}
		}
		if (found || (__SIZE_TYPE__)n < (long)sizeof(buf)) break;
	}
	LINUX_SYSCALL1(__NR_close, efd);
	return found;
}

void __dserver_ring_maybe_run_duplex_selftest(void) {
	static int ran = 0;
	if (ran) {
		return; // one-shot per process
	}
	ran = 1;
	if (!gr_duplex_selftest_enabled()) {
		return; // env not set -> strict no-op (every daemon on a normal boot)
	}
	// Skip guest init (launchd == guest-pid 1) defensively.
	if ((int)LINUX_SYSCALL(__NR_getpid) == 1) {
		return;
	}
	uint32_t arg = 0xC0FFEE42u;
	uint32_t result = 0;
	int rc = __dserver_ring_duplex_selftest(arg, &result);
	uint32_t expect = dserver_ring_duplex_echo_transform(arg);
	// stable, greppable single line for the D3 gate. PASS only iff rc==0 AND echo matches.
	if (rc == 0 && result == expect) {
		__simple_fprintf(2, "[dring-duplex-selftest] PASS rc=0 arg=0x%x result=0x%x expect=0x%x\n",
			arg, result, expect);
	} else {
		__simple_fprintf(2, "[dring-duplex-selftest] FAIL rc=%d arg=0x%x result=0x%x expect=0x%x\n",
			rc, arg, result, expect);
	}
}

// === perf #18 P8 D4 (dar-1il.3.2.1): mach_port_deallocate over the DUPLEX lane =====================
//
// deallocate is destroy-capable: dropping the last ref of a mapped-region-backed port drives a
// vm-munmap S2C upcall to THIS caller. Over the SIMPLE ring a futex-parked caller can't service that
// S2C -> deadlock (dar-1il.1), so it stayed UDS-only. The duplex lane fixes exactly this: the caller,
// while parked for the deallocate's final reply, ALSO pumps the munmap S2C on its own thread.
//
// ROUTING (the membership/safety contract): the guest sends deallocate on the duplex lane ONLY behind a
// per-command hatch (DARLING_GUEST_DUPLEX_DEALLOCATE=1, default OFF, warm-server discipline) AND only
// after advertising DSERVER_RING_DUPLEX_CAP_DEALLOCATE at attach. This routing decision is made BEFORE
// the request is published (pre-dispatch) -- so a decline is always pre-mutation and there is never a
// partial-mutation-then-UDS double-effect. On ANY transport miss (no ring / ring full / give-up / a
// server decline reply) the caller returns -1 and the trap impl UDS-falls-back, which is safe because
// the server declines BEFORE dispatching the op (it never began mutating).

// The hatch: scan /proc/self/environ libc-free for DARLING_GUEST_DUPLEX_DEALLOCATE=1. Same discipline
// as the selftest trigger -- set ONLY per-command on a warm server, never at boot (daemons must not
// inherit it). Cached after the first scan (the env is fixed for the process lifetime).
static int gr_dealloc_via_duplex_enabled(void) {
	static int cached = -1;
	if (cached >= 0) {
		return cached;
	}
	cached = 0;
	long efd = LINUX_SYSCALL(__NR_open, "/proc/self/environ", 0 /*O_RDONLY*/, 0);
	if (efd < 0) {
		return 0;
	}
	static const char key[] = "DARLING_GUEST_DUPLEX_DEALLOCATE=1";
	const __SIZE_TYPE__ keylen = sizeof(key) - 1;
	char buf[4096];
	int found = 0;
	for (;;) {
		long n = LINUX_SYSCALL(__NR_read, efd, buf, sizeof(buf));
		if (n <= 0) break;
		__SIZE_TYPE__ start = 0;
		for (__SIZE_TYPE__ i = 0; i < (__SIZE_TYPE__)n; ++i) {
			if (buf[i] == '\0') {
				if (i - start == keylen) {
					int eq = 1;
					for (__SIZE_TYPE__ k = 0; k < keylen; ++k) {
						if (buf[start + k] != key[k]) { eq = 0; break; }
					}
					if (eq) found = 1;
				}
				start = i + 1;
			}
		}
		if (found || (__SIZE_TYPE__)n < (long)sizeof(buf)) break;
	}
	LINUX_SYSCALL1(__NR_close, efd);
	cached = found;
	return found;
}

// Try mach_port_deallocate over the duplex lane. Returns 0 on a VALID ring round-trip (writes *out_code
// = the kern_return_t, which the caller uses verbatim); returns -1 only on a pre-publish miss or an
// explicit server DECLINE reply (safe, pre-mutation). Once published, timeout/bad-reply is
// committed-unknown and returns 0 with *out_code=KERN_FAILURE so the caller does NOT UDS-retry.
// Mirrors gr_body_trap's transport but waits with gr_duplex_wait_reply (which pumps the munmap S2C)
// and advertises the deallocate duplex cap.
int __dserver_ring_mach_port_deallocate_duplex(uint32_t target, uint32_t name, int* out_code) {
	if (!gr_dealloc_via_duplex_enabled()) {
		return -1; // hatch off -> UDS (the default path)
	}
	gr_lane_t* L = gr_lane_for_this_thread();
	if (!L) {
		return -1; // no ring for this thread -> UDS fallback
	}
	// advertise that we can pump the munmap S2C upcall shape (the server's duplex guard requires it).
	// release so the server sees the cap before it can observe our deallocate parent request.
	__atomic_store_n(&gr_cb(L)->duplex_caps,
		DSERVER_RING_DUPLEX_CAP_SELFTEST | DSERVER_RING_DUPLEX_CAP_DEALLOCATE, __ATOMIC_RELEASE);

	uint32_t inlineCap = GR_SLOT_SIZE - (uint32_t)sizeof(dserver_ring_slot_t);
	// dserver_call_mach_port_deallocate_t { uint32_t target; uint32_t name; }
	struct { uint32_t target; uint32_t name; } body = { target, name };
	if ((uint32_t)sizeof(body) > inlineCap) {
		return -1;
	}
	dserver_ring_t* c2s = gr_c2s(L);
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -1; // ring full -> UDS fallback
	}
	uint32_t seq = L->seq++;
	req->callnum = (uint32_t)dserver_callnum_mach_port_deallocate;
	req->seq = seq;
	req->length = (uint32_t)sizeof(body);
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	memcpy((char*)req + sizeof(dserver_ring_slot_t), &body, sizeof(body));
	dserver_ring_producer_publish(c2s);
	gr_wake_server(L);

	// wait for the parent's FINAL reply, pumping any munmap S2C upcalls on THIS thread meanwhile.
	gr_wait_result_t wait = gr_duplex_wait_reply(L);
	if (wait.state == GR_WAIT_COMMITTED_UNKNOWN) {
		if (out_code) *out_code = KERN_FAILURE;
		return 0; // published: do NOT retry over UDS
	}
	dserver_ring_slot_t* rep = wait.slot;
	int rc = 0;
	if (out_code) *out_code = KERN_FAILURE; // bad/mismatched reply after publish: no UDS retry
	if (rep->seq == seq && rep->callnum == (uint32_t)dserver_callnum_mach_port_deallocate) {
		if (rep->length >= sizeof(dserver_ring_reply_hdr_t) && rep->length <= inlineCap) {
			char* payload = (char*)rep + sizeof(dserver_ring_slot_t);
			dserver_ring_reply_hdr_t* rh = (dserver_ring_reply_hdr_t*)payload;
			if (rh->code == DSERVER_RING_DUPLEX_DECLINE) {
				// the server declined the duplex deallocate BEFORE dispatching it (no mutation) ->
				// the caller UDS-falls-back. A reserved sentinel code, distinct from any kern_return_t.
				rc = -1;
			} else {
				if (out_code) *out_code = rh->code; // the real kern_return_t
				rc = 0;
			}
		}
	}
	dserver_ring_consumer_advance(gr_s2c(L));
	return rc;
}

// === perf #18 P8 D5 (dar-1il.3.2.2): mach_vm_deallocate over the DUPLEX lane ========================
//
// vm_deallocate is the op that ACTUALLY drives a real caller munmap S2C in Darling: the server's
// vm_map_remove -> dtape_hook_task_free_pages -> Process::freePages -> Thread::_munmap -> _s2cPerform
// sends a munmap upcall back to THIS caller. Over the SIMPLE ring a futex-parked caller can't service
// that S2C -> the dar-1il.1 deadlock. The duplex lane fixes exactly this (the caller pumps the munmap
// S2C on its own thread while parked) -- and unlike D4's mach_port_deallocate (whose S2C is unreachable
// because make_memory_entry is a stub), vm_deallocate REALLY fires it, so this is the live cure proof.
//
// Reuses the D4 duplex munmap transport VERBATIM (gr_duplex_pump_once already handles UPCALL_MUNMAP, the
// mailbox + gr_duplex_wait_reply are unchanged); the only new thing is the routing for THIS callnum
// behind its own cap + per-command hatch. Same safety contract: routing is decided PRE-DISPATCH from the
// negotiated cap (a decline is always pre-mutation, never partial-mutation-then-UDS).

// D5 boot-scoped proof arming (gist 3e928115). Two arming paths, BOTH default OFF; cached after the first
// check (arming is fixed for a process lifetime):
//   (1) a per-command ENV hatch DARLING_GUEST_DUPLEX_VM_DEALLOCATE=1 -- for WARM-server leaf testing, the
//       D4 discipline (never set at boot: a stalling op inherited by a daemon would wedge shellspawn).
//   (2) a boot-scoped MARKER FILE at a fixed guest-visible path -- the ONLY safe way to arm launchd (guest
//       pid 1) at boot WITHOUT inheriting an env into shellspawn/leaf daemons. The harness creates the
//       marker before the proof boot and removes it after, so exactly one boot is armed. A marker is NOT
//       inherited across exec the way env is; each process independently stats it. The server's own
//       conjunction (armed budget + pid==1) is the real gate -- this just lets launchd OFFER the op; the
//       server still declines pre-mutation for every non-pid-1 / unarmed caller, so a stray marker is safe.
// The path lives under the guest's writable runtime dir; the harness maps it to the host prefix.
#define DSERVER_D5_PROOF_MARKER "/private/var/run/darling_d5_vmdealloc_proof"
static int gr_vm_dealloc_via_duplex_enabled(void) {
	static int cached = -1;
	if (cached >= 0) {
		return cached;
	}
	cached = 0;
	// (2) marker file first (cheap stat). If present, arm. Scoped to the proof boot.
	{
		long mfd = LINUX_SYSCALL(__NR_open, DSERVER_D5_PROOF_MARKER, 0 /*O_RDONLY*/, 0);
		if (mfd >= 0) {
			LINUX_SYSCALL1(__NR_close, mfd);
			cached = 1;
			return 1;
		}
	}
	// (1) env hatch (warm leaf testing).
	long efd = LINUX_SYSCALL(__NR_open, "/proc/self/environ", 0 /*O_RDONLY*/, 0);
	if (efd < 0) {
		return 0;
	}
	static const char key[] = "DARLING_GUEST_DUPLEX_VM_DEALLOCATE=1";
	const __SIZE_TYPE__ keylen = sizeof(key) - 1;
	char buf[4096];
	int found = 0;
	for (;;) {
		long n = LINUX_SYSCALL(__NR_read, efd, buf, sizeof(buf));
		if (n <= 0) break;
		__SIZE_TYPE__ start = 0;
		for (__SIZE_TYPE__ i = 0; i < (__SIZE_TYPE__)n; ++i) {
			if (buf[i] == '\0') {
				if (i - start == keylen) {
					int eq = 1;
					for (__SIZE_TYPE__ k = 0; k < keylen; ++k) {
						if (buf[start + k] != key[k]) { eq = 0; break; }
					}
					if (eq) found = 1;
				}
				start = i + 1;
			}
		}
		if (found || (__SIZE_TYPE__)n < (long)sizeof(buf)) break;
	}
	LINUX_SYSCALL1(__NR_close, efd);
	cached = found;
	return found;
}

// Try mach_vm_deallocate over the duplex lane. Returns 0 on a VALID ring round-trip (writes *out_code =
// the kern_return_t verbatim); returns -1 only on a pre-publish miss or an explicit server DECLINE reply
// (safe, pre-mutation). Once published, timeout/bad-reply is committed-unknown and returns 0 with
// *out_code=KERN_FAILURE so the caller does NOT UDS-retry. Mirrors
// __dserver_ring_mach_port_deallocate_duplex but with the vm_deallocate body
// {uint32 target; uint64 address; uint64 size} and the VM_DEALLOCATE cap.
// Set by the D6 proof driver (below) while it intentionally drives ONE vm_deallocate over the duplex lane,
// so the duplex function proceeds without the production hatch (the D6 proof has its own marker gate + the
// server arming + budget bound the blast radius). Default 0 -> the production hatch governs.
static int g_d6_proof_force = 0;
int __dserver_ring_mach_vm_deallocate_duplex(uint32_t target, uint64_t address, uint64_t size, int* out_code) {
	if (!g_d6_proof_force && !gr_vm_dealloc_via_duplex_enabled()) {
		return -1; // hatch off -> UDS (the default path)
	}
	gr_lane_t* L = gr_lane_for_this_thread();
	if (!L) {
		return -1; // no ring for this thread -> UDS fallback
	}
	// advertise that we can pump the munmap S2C upcall shape for a vm_deallocate parent. release so the
	// server sees the cap before it can observe our vm_deallocate parent request. We OR in (not overwrite)
	// so a process that already advertised SELFTEST/DEALLOCATE keeps those.
	uint32_t prev = __atomic_load_n(&gr_cb(L)->duplex_caps, __ATOMIC_ACQUIRE);
	__atomic_store_n(&gr_cb(L)->duplex_caps,
		prev | DSERVER_RING_DUPLEX_CAP_SELFTEST | DSERVER_RING_DUPLEX_CAP_VM_DEALLOCATE, __ATOMIC_RELEASE);

	uint32_t inlineCap = GR_SLOT_SIZE - (uint32_t)sizeof(dserver_ring_slot_t);
	// dserver_call_mach_vm_deallocate_t { uint32_t target; uint64_t address; uint64_t size; } -- the
	// uint64 fields are 8-byte aligned, so the struct is 24 bytes (4 + 4 pad + 8 + 8). Build it with the
	// generated type so the layout matches the server's sizeof(dserver_call_mach_vm_deallocate_t) check.
	dserver_call_mach_vm_deallocate_t body;
	body.target = target;
	body.address = address;
	body.size = size;
	if ((uint32_t)sizeof(body) > inlineCap) {
		return -1;
	}
	dserver_ring_t* c2s = gr_c2s(L);
	dserver_ring_slot_t* req = dserver_ring_producer_begin(c2s, GR_SLOT_SIZE, GR_SLOT_COUNT);
	if (!req) {
		return -1; // ring full -> UDS fallback
	}
	uint32_t seq = L->seq++;
	req->callnum = (uint32_t)dserver_callnum_mach_vm_deallocate;
	req->seq = seq;
	req->length = (uint32_t)sizeof(body);
	req->arena_off = 0;
	req->arena_len = 0;
	req->flags = 0;
	memcpy((char*)req + sizeof(dserver_ring_slot_t), &body, sizeof(body));
	dserver_ring_producer_publish(c2s);
	gr_wake_server(L);

	// wait for the parent's FINAL reply, pumping any munmap S2C upcalls on THIS thread meanwhile.
	gr_wait_result_t wait = gr_duplex_wait_reply(L);
	if (wait.state == GR_WAIT_COMMITTED_UNKNOWN) {
		// PUBLISHED-then-TIMEOUT (bounded ~3s). CRITICAL: we have ALREADY published the parent onto the
		// duplex lane, so the SERVER owns this op now -- it may have already performed the munmap. We must
		// NOT UDS-fall-back here (that would re-run vm_deallocate = a potential double munmap of a range
		// that may have been re-mapped = the MODEL-B hazard). Report a normal kern_return_t failure without
		// retry; GREEN never trips this branch.
		if (out_code) *out_code = KERN_FAILURE;
		return 0;
	}
	dserver_ring_slot_t* rep = wait.slot;
	int rc = 0;
	if (out_code) *out_code = KERN_FAILURE; // bad/mismatched reply after publish: no UDS retry
	if (rep->seq == seq && rep->callnum == (uint32_t)dserver_callnum_mach_vm_deallocate) {
		if (rep->length >= sizeof(dserver_ring_reply_hdr_t) && rep->length <= inlineCap) {
			char* payload = (char*)rep + sizeof(dserver_ring_slot_t);
			dserver_ring_reply_hdr_t* rh = (dserver_ring_reply_hdr_t*)payload;
			if (rh->code == DSERVER_RING_DUPLEX_DECLINE) {
				// server declined pre-dispatch (no mutation) -> caller UDS-falls-back.
				rc = -1;
			} else {
				if (out_code) *out_code = rh->code; // the real kern_return_t
				rc = 0;
			}
		}
	}
	dserver_ring_consumer_advance(gr_s2c(L));
	return rc;
}

// === perf #18 P8 D6 (caller-S2C sideband): synthetic WARM real-munmap proof ==========================
//
// The conclusive D5/D6 attribution: no guest sends a vm_deallocate RPC, and the only real caller-S2C
// munmap carrier (mach_msg_overwrite) is UDS-only -> no PRODUCTION op drives a caller-S2C over the ring
// today. To prove the duplex caller-S2C sideband LIVE on the REAL transport (not the synthetic D3 echo),
// this test-only driver: (1) mmaps a real page in THIS guest's address space; (2) sends a vm_deallocate
// of that page with target==mach_task_self() OVER the duplex ring, BYPASSING the trap's local-munmap gate
// (__dserver_ring_mach_vm_deallocate_duplex publishes straight to the c2s ring). On the server,
// _kernelrpc_mach_vm_deallocate_trap resolves target to the CURRENT task and frees the page via
// vm_map_remove -> task_free_pages -> a REAL munmap S2C back to THIS (ring-parked) caller, which rides the
// duplex mailbox. We pump it on this thread (real munmap(2)), the server fiber resumes, and the final
// parent reply returns over the ring. This exercises the ENTIRE real mechanism end-to-end.
//
// Triggered by a MARKER FILE (/private/tmp/.dring-d6-munmap-go), one-shot, warm-server discipline (never
// at boot). The server must be ARMED (DARLING_SERVER_D5_VMDEALLOC_PROOF=<budget>) or it declines
// pre-dispatch (the guest then UDS-falls-back harmlessly -- but since we deallocate our OWN just-mapped
// page, a decline means the page stays mapped, which is safe).
static int gr_d6_munmap_proof_enabled(void) {
	// Trigger = the ENV var DARLING_GUEST_D6_MUNMAP_PROOF=1 on the leaf command (the PROVEN D3 selftest
	// pattern: shellspawn is already running WITHOUT it, so only the explicitly-targeted leaf inherits it
	// and runs the proof -- safe per-command on a warm server, never at boot). The per-process duplex wait
	// is BOUNDED so even an unexpected inheritor cannot wedge. Scanned libc-free from /proc/self/environ.
	long efd = LINUX_SYSCALL(__NR_open, "/proc/self/environ", 0 /*O_RDONLY*/, 0);
	if (efd < 0) {
		return 0;
	}
	static const char key[] = "DARLING_GUEST_D6_MUNMAP_PROOF=1";
	const __SIZE_TYPE__ keylen = sizeof(key) - 1;
	char buf[4096];
	int found = 0;
	for (;;) {
		long n = LINUX_SYSCALL(__NR_read, efd, buf, sizeof(buf));
		if (n <= 0) break;
		__SIZE_TYPE__ start = 0;
		for (__SIZE_TYPE__ i = 0; i < (__SIZE_TYPE__)n; ++i) {
			if (buf[i] == '\0') {
				if (i - start == keylen) {
					int eq = 1;
					for (__SIZE_TYPE__ k = 0; k < keylen; ++k) {
						if (buf[start + k] != key[k]) { eq = 0; break; }
					}
					if (eq) found = 1;
				}
				start = i + 1;
			}
		}
		if (found || (__SIZE_TYPE__)n < (long)sizeof(buf)) break;
	}
	LINUX_SYSCALL1(__NR_close, efd);
	return found;
}

void __dserver_ring_maybe_run_d6_munmap_proof(uint32_t self_task_name) {
	static int ran = 0;
	if (ran) return;
	ran = 1;
	if (!gr_d6_munmap_proof_enabled()) {
		return; // env trigger absent -> strict no-op (every normal process)
	}
	// (1) mmap a real anonymous page locally (PROT_READ|WRITE, MAP_PRIVATE|ANON).
	long pg = LINUX_SYSCALL(__NR_mmap, 0, 4096, 0x3 /*RW*/, 0x22 /*PRIVATE|ANON*/, -1, 0);
	if (pg < 0 || pg == 0) {
		__simple_fprintf(2, "[dring-d6-munmap] FAIL mmap rc=%ld\n", pg);
		return;
	}
	*((volatile char*)pg) = 0x5A; // fault the page in so there is something to munmap.
	// (2) send vm_deallocate of THAT page over the duplex ring with our task-self port name (the server
	// trap resolves it to current_task() and frees OUR map -> real munmap S2C back to this ring-parked
	// caller, which rides the duplex mailbox). self_task_name is the caller's mach_task_self() name.
	int code = 0xDEAD;
	g_d6_proof_force = 1; // let the duplex function proceed without the production hatch (proof gate above)
	int rc = __dserver_ring_mach_vm_deallocate_duplex(self_task_name, (uint64_t)pg, 4096, &code);
	g_d6_proof_force = 0;
	if (rc == 0) {
		__simple_fprintf(2, "[dring-d6-munmap] PASS rc=0 code=%d addr=0x%lx (real caller-S2C munmap over duplex)\n", code, (unsigned long)pg);
	} else {
		__simple_fprintf(2, "[dring-d6-munmap] FAIL rc=%d (server declined / transport miss -- not armed?)\n", rc);
	}
}

int __dserver_ring_mach_port_insert_right(uint32_t target, uint32_t name, uint32_t poly, int32_t polyPoly, int* out_code) {
	// dserver_call_mach_port_insert_right_t { uint32_t target; uint32_t name; uint32_t poly; int32_t polyPoly; }
	struct {
		uint32_t target;
		uint32_t name;
		uint32_t poly;
		int32_t  polyPoly;
	} body = { target, name, poly, polyPoly };
	return gr_body_trap((uint32_t)dserver_callnum_mach_port_insert_right, &body, (uint32_t)sizeof(body), out_code);
}

#endif // DARLING_RING_TRANSPORT
