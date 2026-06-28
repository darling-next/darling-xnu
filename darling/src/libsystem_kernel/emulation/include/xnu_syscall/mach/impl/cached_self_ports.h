// perf #7 (dar-dar6x4-perf-5dq.14): cache the process-stable Mach self-port traps.
//
// The real-build profile (perf #9, dar-dar6x4-perf-5dq.16) showed task_self_trap is
// ~13% of ALL RPCs in a fork/exec-heavy build -- called ~6x per process even though
// the task self port is IMMUTABLE for a process's lifetime. macOS itself treats it as
// a one-shot: libsyscall caches task_self_trap() once into the `mach_task_self_` macro
// and never traps again, and nobody ever mach_port_deallocate()s it. So every trap
// after the first is a pure, redundant RPC round-trip -- 57% of guest wall-clock is
// spent asleep waiting for exactly these replies (perf #6).
//
// This caches the self-port name in a process-global after the first real trap and
// returns the cached name thereafter. It is fork-safe: the cache MUST be reset in the
// atfork-child path BEFORE anything reads it (a forked child is a new task with a new
// self port), via cached_self_port_reset(). mach_init_doit() -- which runs at both
// process init and in _mach_fork_child() -- is the single reset point.
//
// Why only task/thread self (not host self): host_self_trap() returns a send right the
// CALLER is expected to mach_port_deallocate() (the documented mach_host_self contract),
// so collapsing N calls to one name without N server-side ref increments would
// over-release the port. task/thread self ports are never deallocated by their macros,
// so collapsing them is semantically transparent.
//
// Kept header-only + dependency-injected (the trap fn is passed in) so it can be unit
// tested hermetically off-target. MACH_PORT_NULL (0) is the "empty" sentinel; a real
// self port is never 0, so a populated cache is unambiguous.

#ifndef _DARLING_CACHED_SELF_PORTS_H_
#define _DARLING_CACHED_SELF_PORTS_H_

#include <stdint.h>

typedef uint32_t cached_port_name_t;
#ifndef CACHED_MACH_PORT_NULL
#define CACHED_MACH_PORT_NULL ((cached_port_name_t)0)
#endif

// One cache slot. Plain (non-atomic) is correct for task/host self because the value is
// process-stable and identical regardless of which thread fills it first: a benign race
// only means two threads both perform the first trap and store the same name. For the
// thread-self slot the storage must be thread-local (the caller decides), but the logic
// is identical, so the same helper serves both.
typedef struct {
	cached_port_name_t name;
} cached_self_port_t;

// Return the cached self-port name, performing the real trap exactly once (per reset
// epoch) via do_trap(). On a trap failure (returns CACHED_MACH_PORT_NULL) nothing is
// cached, so the next call retries -- a transient RPC failure never poisons the cache.
static inline cached_port_name_t cached_self_port_get(cached_self_port_t* slot,
                                                      cached_port_name_t (*do_trap)(void)) {
	cached_port_name_t cached = slot->name;
	if (cached != CACHED_MACH_PORT_NULL) {
		return cached;
	}
	cached_port_name_t fresh = do_trap();
	if (fresh != CACHED_MACH_PORT_NULL) {
		slot->name = fresh;
	}
	return fresh;
}

// Drop the cached value so the next get() performs a fresh trap. Call from the
// atfork-child path (a forked child is a new task -> new self port).
static inline void cached_self_port_reset(cached_self_port_t* slot) {
	slot->name = CACHED_MACH_PORT_NULL;
}

#endif // _DARLING_CACHED_SELF_PORTS_H_
