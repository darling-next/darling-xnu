// perf #7 (dar-dar6x4-perf-5dq.14) regression test: process-stable self-port caching.
//
// The real-build profile (perf #9) showed task_self_trap = ~13% of ALL RPCs, called
// ~6x per process for an IMMUTABLE value. cached_self_ports.h collapses those to one
// real trap per process (per fork epoch). This test pins the two properties the win
// AND the correctness depend on:
//   1. SUPPRESSION: N gets perform exactly ONE real trap (the rest hit the cache).
//   2. FORK-RESET: after reset() the next get performs a fresh trap and adopts the new
//      value -- so a forked child (new task, new self port) never returns the parent's
//      stale port.
//   3. FAILURE-SAFE: a trap that fails (returns NULL) is not cached, so the next get
//      retries (a transient RPC error must not poison the cache forever).
//
// RED->GREEN: a non-caching implementation (trap on every get) fails property 1
// (trap_calls == N, not 1). The header's cache makes it 1. Hermetic: host-compiled,
// no darlingserver, no boot. Exit 0 = GREEN.

#include <xnu_syscall/mach/impl/cached_self_ports.h>

#include <stdio.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
	if (!(cond)) { fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); ++failures; } \
} while (0)

// A mock trap: counts how many times the "RPC" actually fired, and returns a
// controllable value (so we can simulate a fork changing the self port, and a failure).
static int trap_calls = 0;
static cached_port_name_t trap_value = 0;
static cached_port_name_t mock_trap(void) {
	++trap_calls;
	return trap_value;
}

int main(void) {
	cached_self_port_t slot = { CACHED_MACH_PORT_NULL };

	// ---- 1. suppression: 1000 gets, exactly one real trap ----
	trap_value = 0x103;   // a plausible self-port name (non-zero)
	trap_calls = 0;
	cached_port_name_t first = cached_self_port_get(&slot, mock_trap);
	CHECK(first == 0x103, "first get returns the trapped value");
	for (int i = 0; i < 999; ++i) {
		cached_port_name_t v = cached_self_port_get(&slot, mock_trap);
		CHECK(v == 0x103, "cached gets return the same value");
	}
	CHECK(trap_calls == 1, "1000 gets perform exactly ONE real trap (suppression)");

	// ---- 2. fork-reset: after reset, a fresh trap adopts the new (child) value ----
	trap_value = 0x207;   // the child's new self port
	cached_self_port_reset(&slot);
	cached_port_name_t afterFork = cached_self_port_get(&slot, mock_trap);
	CHECK(afterFork == 0x207, "after reset, get adopts the NEW self port (fork-safe)");
	CHECK(trap_calls == 2, "reset forces exactly one additional real trap");
	// and it re-caches the new value
	(void) cached_self_port_get(&slot, mock_trap);
	CHECK(trap_calls == 2, "post-reset value is re-cached (no extra trap)");

	// ---- 3. failure-safe: a NULL trap result is not cached; next get retries ----
	cached_self_port_reset(&slot);
	trap_value = CACHED_MACH_PORT_NULL; // simulate a transient trap failure
	cached_port_name_t failed = cached_self_port_get(&slot, mock_trap);
	CHECK(failed == CACHED_MACH_PORT_NULL, "failed trap returns NULL");
	CHECK(trap_calls == 3, "failed trap fired");
	trap_value = 0x305; // RPC recovers
	cached_port_name_t recovered = cached_self_port_get(&slot, mock_trap);
	CHECK(recovered == 0x305, "after a failure the next get retries and succeeds");
	CHECK(trap_calls == 4, "the retry performed a real trap (failure was not cached)");

	if (failures == 0) {
		printf("GREEN: self-port cache suppresses redundant traps, resets on fork, retries on failure\n");
		return 0;
	}
	fprintf(stderr, "RED: %d self-port cache check(s) failed\n", failures);
	return 1;
}
