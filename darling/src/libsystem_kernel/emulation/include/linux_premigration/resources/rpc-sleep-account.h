// perf #9-decompose (dar-dar6x4-perf-5dq): GUEST-SIDE per-callnum recvmsg-sleep
// accountant for the libsystem_kernel emulation RPC path.
//
// perf #6 profiled a real build: the guest spends ~57% of wall-clock asleep in
// recvmsg waiting for an RPC reply, but perf #9 only measured (tiny) SERVER service
// time -- so we never learned WHICH call numbers dominate the guest's reply-wait.
// This accountant times each wrapper's receive (the reply-wait) and attributes the
// elapsed CPU ticks to the call number being waited on. The generated wrapper brackets
// its receive with __darling_rpc_sleep_account_begin()/_end(start, callnum) (see
// generate-rpc-wrappers.py), gated by DARLING_RPC_SLEEP_ACCOUNT -- so a normal build
// never compiles any of this in (zero cost) and only a diagnostic build defines it.
//
// SPLIT: this header provides only the INLINE timing hooks (begin/end) that the wrapper
// calls, referencing the accumulator table by `extern`. The single shared table and the
// dump routine live in rpc-sleep-account.c, compiled exactly ONCE into the emulation
// object library. (The generated rpc.c is compiled into BOTH the `emulation` and
// `emulation_dyld` object libraries; if the table were defined here it would become two
// separate statics -- the running wrappers would fill one while the dump read the other,
// which we observed: dumps fired but every table was empty.)
//
// CONSTRAINTS (see the .c for the full story): libc-free (raw LINUX_SYSCALL, no stdio);
// timebase is rdtsc, NOT clock_gettime (the clock syscall in this send/recv atomic region
// wedges the guest -- bisected); start stamp is a STACK local threaded begin->end (no
// __thread: TLS aborts here pre-pthread); dumped once per process from the clean exit
// path (sys_exit -> __darling_rpc_sleep_dump; NO destructor -- dyld rejects initializers
// in this below-libSystem image).

#ifndef DARLING_RPC_SLEEP_ACCOUNT_H
#define DARLING_RPC_SLEEP_ACCOUNT_H

#ifdef DARLING_RPC_SLEEP_ACCOUNT

#define DARLING_RPC_SLEEP_ACCOUNT_MAX 256

// The single shared accumulators (defined in rpc-sleep-account.c). Unit: TSC ticks.
extern unsigned long __darling_rpc_sleep_count[DARLING_RPC_SLEEP_ACCOUNT_MAX];
extern unsigned long __darling_rpc_sleep_total_ticks[DARLING_RPC_SLEEP_ACCOUNT_MAX];

// Dump the per-process table once, appended to the host log. Defined in the .c; called
// from the clean exit path (sys_exit).
extern void __darling_rpc_sleep_dump(void);

// Timebase: read the CPU timestamp counter directly (rdtsc), NOT clock_gettime. A raw
// LINUX_SYSCALL(__NR_clock_gettime) issued here -- between the RPC send and recv, inside
// the signal-blocked atomic region of the emulation RPC path -- wedges the guest (launchd
// hangs forever in recvmsg; bisected). rdtsc is a plain userspace instruction, no syscall,
// no guest trap, so it is safe here. The unit is CPU ticks; for a per-callnum RANKING of
// where the guest's reply-wait goes (the whole point of this diagnostic) ticks are
// directly comparable across calls.
static inline unsigned long __darling_rpc_now_ticks(void) {
#if defined(__x86_64__) || defined(__i386__)
	unsigned int lo, hi;
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long)hi << 32) | lo;
#elif defined(__aarch64__)
	unsigned long v;
	__asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	return 0;
#endif
}

// The start stamp is carried in a STACK local in the generated wrapper (begin returns it,
// end takes it) -- NOT in thread-local storage (TLS aborts here pre-pthread).
static inline unsigned long __darling_rpc_sleep_account_begin(void) {
	return __darling_rpc_now_ticks();
}

static inline void __darling_rpc_sleep_account_end(unsigned long start_ticks, unsigned int callnum) {
	unsigned long elapsed = __darling_rpc_now_ticks() - start_ticks;
	unsigned idx = callnum & (DARLING_RPC_SLEEP_ACCOUNT_MAX - 1);
	// Plain non-atomic accumulate: the table is touched only between begin/end on the
	// calling thread; concurrent threads race at most to lose/duplicate a sample, fine
	// for a coarse ranking. Indexed by (callnum & 0xff): UNMANAGED calls carry a high
	// bit, so masking folds them onto their low byte.
	__darling_rpc_sleep_count[idx] += 1;
	__darling_rpc_sleep_total_ticks[idx] += elapsed;
}

#endif // DARLING_RPC_SLEEP_ACCOUNT

#endif // DARLING_RPC_SLEEP_ACCOUNT_H
