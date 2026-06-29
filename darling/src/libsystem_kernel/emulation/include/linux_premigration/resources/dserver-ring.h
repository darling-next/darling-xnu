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

// Fast path for task_self_trap over the ring. On success writes *out_port + returns 0 (the
// same contract as dserver_rpc_task_self_trap). Returns a negative value if the ring is
// unavailable / the op isn't ring-eligible / anything went wrong -> caller MUST fall back to
// the UDS wrapper. Never blocks unboundedly: it bounded-spins then FUTEX_WAITs for the reply.
int __dserver_ring_task_self_trap(uint32_t* out_port);

// Reset ring state in the forked child (the parent's ring + wake fd are not valid post-fork;
// the child re-attaches lazily). Called from the fork path alongside the socket refresh.
void __dserver_ring_postfork_reset(void);

#else // !DARLING_RING_TRANSPORT

// Folded-away stubs so call sites compile to nothing extra when the feature is off.
static inline bool __dserver_ring_try_attach(void) { return false; }
static inline int __dserver_ring_task_self_trap(uint32_t* out_port) { (void)out_port; return -1; }
static inline void __dserver_ring_postfork_reset(void) {}

#endif // DARLING_RING_TRANSPORT

#endif // _DARLING_DSERVER_RING_H_
