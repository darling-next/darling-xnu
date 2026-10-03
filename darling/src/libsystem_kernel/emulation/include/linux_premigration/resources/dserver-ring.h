// perf #18 (dar-dar6x4-perf-5dq.30) P3: GUEST-side shared-memory ring transport.
//
// The guest builds a memfd holding a dserver_ring_shm control block + two SPSC rings, hands
// it to the server via the ring_attach RPC (which returns a wake eventfd), then for eligible
// calls publishes a request onto the c2s ring + writes the wake eventfd and waits for the
// reply on the s2c ring instead of paying a full UDS sendmsg/recvmsg round-trip.
//
// The interface is compiled out unless DARLING_RING_TRANSPORT is enabled for the dylib
// and dyld emulation targets. With it off, helpers return a pre-publication miss and
// call sites use the ordinary UDS wrappers. See dserver-ring.c for the design.

#ifndef _DARLING_DSERVER_RING_H_
#define _DARLING_DSERVER_RING_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef DARLING_RING_TRANSPORT

// One-shot lazy attach for the CURRENT thread/process: build the memfd, fill the control
// block, call ring_attach, map the wake eventfd. Idempotent + cheap after the first call.
// Returns true if a ring is available for this thread to use, false if it must use UDS.
bool __dserver_ring_try_attach(void);

// perf#30 FD-COURIER (PRODUCT): deliver ONE descriptor to the server over the process-scoped
// SCM_RIGHTS channel and return the token that names it, or 0 when the channel cannot take it. A 0
// return means the caller keeps its descriptor and uses the legacy transport for the WHOLE call: the
// two halves of an operation are never split across transports, and a published operation is never
// silently downgraded. ONE connection per Linux process, reused for every transfer.
uint64_t __dserver_fd_courier_send(int fd, uint32_t kind);
// perf#30 FD-COURIER (SERVER->GUEST): resolve a token the server named in a reply to the descriptor it
// hands this process. -1 means the courier could not deliver it, which is a committed failure of the
// operation that named the token -- never a silent "no descriptor".
int __dserver_fd_courier_receive(uint64_t token);
void __dserver_fd_courier_postfork_reset(void);


// Fast path for the no-arg, single-uint32-port-reply traps over the ring. On success writes
// *out_port + returns 0 (the same contract as the matching dserver_rpc_* wrapper). Returns a
// negative value only if the request was not published and the caller may safely fall back to the
// UDS wrapper. Once published, timeout/bad-reply is committed-unknown and returns KERN_FAILURE
// without retrying. Never blocks unboundedly: it bounded-spins then FUTEX_WAITs for the reply.
//
// task_self_trap is cached per-process (perf #7) so it's correctness-first; mach_reply_port is
// the UNCACHED high-frequency op that actually exercises the ring's latency win.
int __dserver_ring_task_self_trap(uint32_t* out_port);
// perf #18 D10 (dar-1il.5): thread_self_trap + host_self_trap, the remaining pure-mint self-trap
// family (same empty-request/port-reply shape as task_self_trap). Uncached (unlike task_self_trap):
// thread_self_trap is per-thread, host_self_trap left uncached to keep this bead minimal -- the win is
// the ring transport, not caching (perf#7, orthogonal). 0 on a valid round-trip; negative only before publish.
int __dserver_ring_thread_self_trap(uint32_t* out_port);
int __dserver_ring_host_self_trap(uint32_t* out_port);
int __dserver_ring_mach_reply_port(uint32_t* out_port);

// perf #18 P5-bulk: small-inline-body ops with a header-only reply. On a valid ring round-trip each
// writes *out_code (the kern_return_t -- use it verbatim, it may be an error like KERN_INVALID_NAME)
// and returns 0; returns negative only if the request was not published and the caller may safely fall
// back to the UDS wrapper. After publish, timeout/bad-reply returns 0 with *out_code=KERN_FAILURE so the
// operation is not re-run over UDS.
// The result code and the fall-back signal are SEPARATE (a kern_return_t can be any value). Any
// out-value travels via the guest-memory write the generic Call path already performs, e.g.
// mach_port_allocate's `name`; name_ptr (allocate) is the guest VA.
//
// NOTE: mach_port_mod_refs has NO ring helper (dar-1il.2) -- it is destroy-capable and was removed
// from DSERVER_RING_C2S_OPCODES (negative-delta last-ref destroy -> vm munmap S2C upcall to a
// ring-parked caller -> deadlock; same class as mach_port_deallocate). It is UDS-only. The
// mach_port_deallocate helper below is likewise dead (deallocate reverted to UDS-only in dar-1il.1)
// and kept only to minimize that diff.
int __dserver_ring_mach_port_deallocate(uint32_t target, uint32_t name, int* out_code);

// perf#29 (GENERATED-WRAPPER RING ROUTE): the tri-state result of a Ring attempt made from a GENERATED
// client wrapper. The generated code must never treat "the request may already have been published" as
// "try the datagram path" -- that would run a state-mutating RPC twice -- so the transport result is
// three-valued instead of the ambiguous -1 the older helpers return.
#define GR_RING_TRY_NOT_TAKEN 0          // nothing was published: the datagram path is still safe
#define GR_RING_TRY_COMPLETED 1          // the Ring transaction completed; the reply is staged
#define GR_RING_TRY_COMMITTED_FAILURE 2  // PUBLISHED but failed/unknown: UDS retry is FORBIDDEN
int __dserver_ring_environ_has(const char* key, __SIZE_TYPE__ keylen);
int __dserver_ring_try_generated_rpc(uint32_t callnum, const void* req_body, uint32_t req_body_len,
                                     void* reply_body, uint32_t reply_body_len, int32_t* out_code);
int __dserver_ring_mach_port_allocate(uint32_t target, int32_t right, uint64_t name_ptr, int* out_code);
int __dserver_ring_mach_port_insert_right(uint32_t target, uint32_t name, uint32_t poly, int32_t polyPoly, int* out_code);

// Closed BSD/internal RPCs (generic-fiber lane). The required *out_code receives the
// operation status: 0 on success, negative Linux errno on failure. Out-values are copied
// only on success. The helper returns negative only before publication, permitting UDS
// fallback; after publication it returns 0, including committed-unknown, which sets
// *out_code=-LINUX_EIO without retrying. Replies carry a fixed body except for the
// header-only set_thread_handles. None is destroy-capable or caller-S2C.
int __dserver_ring_uidgid(int32_t new_uid, int32_t new_gid, int32_t* out_old_uid, int32_t* out_old_gid, int* out_code);
int __dserver_ring_set_thread_handles(uint64_t pthread_handle, uint64_t dispatch_qaddr, int* out_code);
int __dserver_ring_started_suspended(bool* out_suspended, int* out_code);
int __dserver_ring_get_tracer(int32_t* out_tracer, int* out_code);
int __dserver_ring_task_is_64_bit(int32_t id, bool* out_is_64_bit, int* out_code);

// perf #18 D13 (dar-1il.8): path ops. The char*/path is delivered via the server's writeMemory on the
// guest /proc/mem (transport-agnostic), so the ring body is the FIXED { uint64_t buffer; uint64_t
// buffer_size; } and the reply is { uint64_t length; } -- NO arena. These use the same
// BSD/internal status contract above: out_length is set only on success; committed-unknown
// returns 0 with *out_code=-LINUX_EIO, never UDS fallback.
int __dserver_ring_vchroot_path(uint64_t buffer, uint64_t buffer_size, uint64_t* out_length, int* out_code);
int __dserver_ring_mldr_path(uint64_t buffer, uint64_t buffer_size, uint64_t* out_length, int* out_code);

// Reset image-local mappings in the forked child after the shared loader closes
// inherited ring FDs. This must not close saved FD numbers; the child re-attaches lazily.
void __dserver_ring_postfork_reset(void);

// perf #18 D17 (dar-1il.12): dump this process's per-thread lane stats (acquired / exhausted / reclaimed
// / held-now) to stderr ONCE on the clean exit path. RECON-only, strict no-op unless DARLING_GUEST_LANE_
// STATS=1. Mirrors __darling_rpc_sleep_dump's exit-path hook so it's robust without a dylib fini handler.
void __dserver_ring_lane_stats_dump(void);
// perf#27: return THIS thread's lane slot to the catalog (thread-exit path).
void __dserver_ring_release_current_lane(void);
// perf#27: process-scoped transport accounting (opt-in trace) + the UDS-fallback mark for mach_msg.
void __dserver_ring_proc_event(const char* direction, const char* transport, uint32_t lane, uint32_t seq,
                               uint32_t callnum);
void __dserver_ring_note_uds_machmsg(void);

// perf #18 P8 D3 (dar-1il.3.1.1): the synthetic DUPLEX-lane selftest. Advertises the SELFTEST duplex
// capability, publishes the sentinel parent request carrying `arg`, runs the duplex wait-pump (services
// the S2C upcall mailbox on THIS thread while waiting for the parent's final reply), and on success
// writes the echo result (== arg ^ 0x5A5A5A5A) to *out_result + returns 0. Returns negative on
// transport/server failure; this selftest has no UDS retry path. Drives the REAL ring + server
// _drainDuplexReply + guest pump end-to-end. Only reached when both sides opt in (server hatch
// DARLING_SERVER_DUPLEX_SELFTEST=1, and the guest driver __dserver_ring_maybe_run_duplex_selftest
// below, gated DARLING_GUEST_DUPLEX_SELFTEST=1).
int __dserver_ring_duplex_selftest(uint32_t arg, uint32_t* out_result);

// One-shot guest driver, gated by the env var DARLING_GUEST_DUPLEX_SELFTEST=1. SAFETY DISCIPLINE: the
// harness sets this env ONLY on the per-command `darling shell` invocation against an ALREADY-WARM
// server -- NEVER at boot. So daemons (launchd, shellspawn), started before the env existed, never run
// the selftest; only the explicitly-targeted leaf process does, prints a single stable stderr line the
// D3 gate greps, and exits. (Setting the env at BOOT inherits it into shellspawn and wedges it -- don't.)
// A strict no-op when the env is unset. Call it from an early trap (task_self_trap).
void __dserver_ring_maybe_run_duplex_selftest(void);

// perf #18 P8 D4 (dar-1il.3.2.1): try mach_port_deallocate over the DUPLEX lane. The destroy-capable op
// the duplex lane exists for: dropping the last ref of a mapped-region-backed port drives a vm-munmap
// S2C upcall to THIS caller, which the caller pumps on its own thread while parked for the final reply
// (impossible over the simple ring -> the dar-1il.1 deadlock). On a valid ring round-trip writes
// *out_code (the kern_return_t, verbatim) + returns 0; returns negative only before publish OR after an
// explicit server pre-mutation DECLINE reply. After publish, timeout/bad-reply returns 0 with
// *out_code=KERN_FAILURE and never UDS-falls-back, because retrying could double-apply the destroy.
// Routed ONLY behind the per-command hatch DARLING_GUEST_DUPLEX_DEALLOCATE=1 (default OFF, same
// warm-server discipline as the selftest) AND the negotiated DUPLEX_CAP_DEALLOCATE.
// mach_port_mod_refs over the duplex lane: same hazard and same transport as deallocate (a negative
// delta on the last reference can destroy the port and drive a caller munmap S2C), so the same pump.
int __dserver_ring_mach_port_mod_refs_duplex(uint32_t target, uint32_t name, int right, int delta, int* out_code);

int __dserver_ring_mach_port_deallocate_duplex(uint32_t target, uint32_t name, int* out_code);

// perf #18 P8 D5 (dar-1il.3.2.2): try mach_vm_deallocate over the DUPLEX lane. THE op that actually drives
// a real caller munmap S2C in Darling (vm_map_remove -> dtape_hook_task_free_pages -> _munmap ->
// _s2cPerform), so this is the live caller-S2C cure proof D4 could not get. Reuses the D4 duplex munmap
// transport verbatim. On a valid ring round-trip writes *out_code (the kern_return_t, verbatim) + returns
// 0; returns negative only before publish OR after an explicit server pre-mutation DECLINE reply. After
// publish, timeout/bad-reply returns 0 with *out_code=KERN_FAILURE and never UDS-falls-back, because
// retrying could double-apply the deallocation. Routed ONLY behind the per-command hatch
// DARLING_GUEST_DUPLEX_VM_DEALLOCATE=1 (default OFF) AND the negotiated DUPLEX_CAP_VM_DEALLOCATE.
int __dserver_ring_mach_vm_deallocate_duplex(uint32_t target, uint64_t address, uint64_t size, int* out_code);
// perf#26 RING-MACH-MSG: the first blocking RPC on the lane; publishes the 40-byte mach_msg_overwrite
// body (msg/rcv_msg are guest addresses) and waits with the duplex pump so a caller-local munmap S2C
// raised on this thread is serviced in the caller's own wait loop.
int __dserver_ring_mach_msg_overwrite(void* msg, int32_t option, uint32_t send_size, uint32_t rcv_size,
                                      uint32_t rcv_name, uint32_t timeout, uint32_t priority, void* rcv_msg,
                                      int* out_code);

// perf #18 P8 D6 (caller-S2C sideband): one-shot synthetic WARM real-munmap proof. Marker-gated
// (/private/tmp/.dring-d6-munmap-go, consumed once); maps a real page then sends vm_deallocate of it over
// the duplex ring (target==self_task_name) so the server frees OUR map -> a REAL caller-S2C munmap rides
// the duplex mailbox = ring_duplex_s2c>0 live. self_task_name is the caller's mach_task_self() port name.
// Strict no-op unless the marker exists. Driven from task_self_trap_impl (early, ring attached).
void __dserver_ring_maybe_run_d6_munmap_proof(uint32_t self_task_name);

#else // !DARLING_RING_TRANSPORT

// Folded-away stubs so call sites compile to nothing extra when the feature is off.
static inline bool __dserver_ring_try_attach(void) { return false; }
static inline int __dserver_ring_task_self_trap(uint32_t* out_port) { (void)out_port; return -1; }
static inline int __dserver_ring_thread_self_trap(uint32_t* out_port) { (void)out_port; return -1; }
static inline int __dserver_ring_host_self_trap(uint32_t* out_port) { (void)out_port; return -1; }
static inline int __dserver_ring_mach_reply_port(uint32_t* out_port) { (void)out_port; return -1; }
static inline int __dserver_ring_mach_port_deallocate(uint32_t target, uint32_t name, int* out_code) { (void)target; (void)name; (void)out_code; return -1; }
static inline int __dserver_ring_mach_port_allocate(uint32_t target, int32_t right, uint64_t name_ptr, int* out_code) { (void)target; (void)right; (void)name_ptr; (void)out_code; return -1; }
static inline int __dserver_ring_mach_port_insert_right(uint32_t target, uint32_t name, uint32_t poly, int32_t polyPoly, int* out_code) { (void)target; (void)name; (void)poly; (void)polyPoly; (void)out_code; return -1; }
static inline int __dserver_ring_uidgid(int32_t new_uid, int32_t new_gid, int32_t* out_old_uid, int32_t* out_old_gid, int* out_code) { (void)new_uid; (void)new_gid; (void)out_old_uid; (void)out_old_gid; (void)out_code; return -1; }
static inline int __dserver_ring_set_thread_handles(uint64_t pthread_handle, uint64_t dispatch_qaddr, int* out_code) { (void)pthread_handle; (void)dispatch_qaddr; (void)out_code; return -1; }
static inline int __dserver_ring_started_suspended(bool* out_suspended, int* out_code) { (void)out_suspended; (void)out_code; return -1; }
static inline int __dserver_ring_get_tracer(int32_t* out_tracer, int* out_code) { (void)out_tracer; (void)out_code; return -1; }
static inline int __dserver_ring_task_is_64_bit(int32_t id, bool* out_is_64_bit, int* out_code) { (void)id; (void)out_is_64_bit; (void)out_code; return -1; }
static inline int __dserver_ring_vchroot_path(uint64_t buffer, uint64_t buffer_size, uint64_t* out_length, int* out_code) { (void)buffer; (void)buffer_size; (void)out_length; (void)out_code; return -1; }
static inline int __dserver_ring_mldr_path(uint64_t buffer, uint64_t buffer_size, uint64_t* out_length, int* out_code) { (void)buffer; (void)buffer_size; (void)out_length; (void)out_code; return -1; }
static inline void __dserver_ring_postfork_reset(void) {}
static inline void __dserver_ring_lane_stats_dump(void) {}
static inline void __dserver_ring_release_current_lane(void) {}
static inline void __dserver_ring_proc_event(const char* d, const char* t, uint32_t l, uint32_t s, uint32_t c)
{ (void)d; (void)t; (void)l; (void)s; (void)c; }
static inline void __dserver_ring_note_uds_machmsg(void) {}
static inline int __dserver_ring_duplex_selftest(uint32_t arg, uint32_t* out_result) { (void)arg; (void)out_result; return -1; }
static inline void __dserver_ring_maybe_run_duplex_selftest(void) {}
static inline int __dserver_ring_mach_port_deallocate_duplex(uint32_t target, uint32_t name, int* out_code) { (void)target; (void)name; (void)out_code; return -1; }
static inline int __dserver_ring_mach_vm_deallocate_duplex(uint32_t target, uint64_t address, uint64_t size, int* out_code) { (void)target; (void)address; (void)size; (void)out_code; return -1; }
static inline int __dserver_ring_mach_msg_overwrite(void* msg, int32_t option, uint32_t send_size, uint32_t rcv_size, uint32_t rcv_name, uint32_t timeout, uint32_t priority, void* rcv_msg, int* out_code) { (void)msg; (void)option; (void)send_size; (void)rcv_size; (void)rcv_name; (void)timeout; (void)priority; (void)rcv_msg; (void)out_code; return -1; }
static inline void __dserver_ring_maybe_run_d6_munmap_proof(uint32_t self_task_name) { (void)self_task_name; }

// perf#30 FD-COURIER: with the transport compiled out there is no process-scoped channel either, so the
// caller keeps its descriptor and uses the legacy path exactly as before.
static inline uint64_t __dserver_fd_courier_send(int fd, uint32_t kind) { (void)fd; (void)kind; return 0; }
static inline int __dserver_fd_courier_receive(uint64_t token) { (void)token; return -1; }
static inline void __dserver_fd_courier_postfork_reset(void) {}

#endif // DARLING_RING_TRANSPORT

#endif // _DARLING_DSERVER_RING_H_
