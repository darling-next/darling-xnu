// perf #18 (dar-dar6x4-perf-5dq.30) P3: GUEST-side shared-memory ring transport.
//
// The guest builds a memfd holding a dserver_ring_shm control block + two SPSC rings, hands
// it to the server via the ring_attach RPC (which returns a wake eventfd), then for eligible
// calls publishes a request onto the c2s ring + writes the wake eventfd and waits for the
// reply on the s2c ring instead of paying a full UDS sendmsg/recvmsg round-trip.
//
// Entire interface is a no-op unless the dylib is built with -DDARLING_RING_TRANSPORT. When
// off, __dserver_ring_enabled() is a compile-time 0 and every call-site fast-path folds away,
// so the build is byte-identical to a non-ring dylib. See dserver-ring.c for the design.

#ifndef _DARLING_DSERVER_RING_H_
#define _DARLING_DSERVER_RING_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef DARLING_RING_TRANSPORT

// One-shot lazy attach for the CURRENT thread/process: build the memfd, fill the control
// block, call ring_attach, map the wake eventfd. Idempotent + cheap after the first call.
// Returns true if a ring is available for this thread to use, false if it must use UDS.
bool __dserver_ring_try_attach(void);

// Fast path for the no-arg, single-uint32-port-reply traps over the ring. On success writes
// *out_port + returns 0 (the same contract as the matching dserver_rpc_* wrapper). Returns a
// negative value if the ring is unavailable / the op isn't ring-eligible / anything went wrong
// -> caller MUST fall back to the UDS wrapper. Never blocks unboundedly: it bounded-spins then
// FUTEX_WAITs for the reply.
//
// task_self_trap is cached per-process (perf #7) so it's correctness-first; mach_reply_port is
// the UNCACHED high-frequency op that actually exercises the ring's latency win.
int __dserver_ring_task_self_trap(uint32_t* out_port);
int __dserver_ring_mach_reply_port(uint32_t* out_port);

// perf #18 P5: small-inline-body op with a header-only reply. On a valid ring round-trip writes
// *out_code (the kern_return_t -- use it verbatim, it may be an error like KERN_INVALID_NAME) and
// returns 0; returns negative on any transport miss -> caller MUST fall back to the UDS wrapper.
// The result code and the fall-back signal are SEPARATE (a kern_return_t can be any value).
int __dserver_ring_mach_port_mod_refs(uint32_t target, uint32_t name, int32_t right, int32_t delta, int* out_code);

// Reset ring state in the forked child (the parent's ring + wake fd are not valid post-fork;
// the child re-attaches lazily). Called from the fork path alongside the socket refresh.
void __dserver_ring_postfork_reset(void);

#else // !DARLING_RING_TRANSPORT

// Folded-away stubs so call sites compile to nothing extra when the feature is off.
static inline bool __dserver_ring_try_attach(void) { return false; }
static inline int __dserver_ring_task_self_trap(uint32_t* out_port) { (void)out_port; return -1; }
static inline int __dserver_ring_mach_reply_port(uint32_t* out_port) { (void)out_port; return -1; }
static inline int __dserver_ring_mach_port_mod_refs(uint32_t target, uint32_t name, int32_t right, int32_t delta, int* out_code) { (void)target; (void)name; (void)right; (void)delta; (void)out_code; return -1; }
static inline void __dserver_ring_postfork_reset(void) {}

#endif // DARLING_RING_TRANSPORT

#endif // _DARLING_DSERVER_RING_H_
