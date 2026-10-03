#ifndef _ELFCALLS_WRAPPER_H
#define _ELFCALLS_WRAPPER_H

#include <elfcalls.h>

#include <darling/emulation/common/base.h>

CPP_EXTERN_BEGIN

// Native library loading
void* native_dlopen(const char* path);
char* native_dlerror(void);
void* native_dlsym(void* module, const char* name);
int native_dlclose(void* module);

void native_exit(int ec);

long native_sysconf(int name);
void __mldr_postfork_child(void);
void __mldr_prefork_prepare(void);
void __mldr_postfork_parent(void);

// Native thread wrapping
void* __darling_thread_create(unsigned long stack_size, unsigned long pthobj_size,
			void* entry_point, uintptr_t arg3,
			uintptr_t arg4, uintptr_t arg5, uintptr_t arg6,
			darling_thread_create_callbacks_t callbacks, void* dthread);

int __darling_thread_terminate(void* stackaddr,
			unsigned long freesize, unsigned long pthobj_size);

void* __darling_thread_get_stack(void);

const void* __dserver_socket_address(void);
const void* __dserver_fd_courier_address(void);
uint64_t __dserver_process_generation(void);
int __dserver_fd_courier_socket(void);
void* __dserver_process_control_page(void);
// perf#30 (directive section 3): the guest image's generic process-management-plane publisher. Returns the
// server's status for a completed request, or -1 meaning "not published / not completed" (fall back).
int __dserver_plane_request(uint32_t op, uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3);
// The SIGNAL-SAFE, non-blocking publisher for the urgent pool (interrupt_enter/interrupt_exit). Returns 0 when
// the publication was made, -1 when there is no transport or no free slot (the caller falls back).
int __dserver_plane_urgent_publish(uint32_t op, uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3);
// The publish-and-poll variant for a signal-context call that needs a completion (sigprocess). Bounded poll,
// no park: signal-safe. Returns the status, or -1 (not published / not completed -> fall back).
int __dserver_plane_urgent_publish_wait(uint32_t op, const uint64_t* words, uint32_t wordCount, int32_t* outStatus, uint64_t* outExtra);
// The variant that also returns the reply payload, for the descriptor-bearing routes whose courier token is
// published there (reply_payload[1]).
int __dserver_plane_request_ex(uint32_t op, uint64_t p0, uint64_t p1, uint64_t p2, uint64_t p3,
	uint64_t* outReply0, uint64_t* outReply1);
void __dserver_fd_courier_reset(void);
int __dserver_process_socket(void);
void __dserver_close_socket(int socket);
int __dserver_adopt_ring_fd(int fd);
void __dserver_release_ring_fd(int fd);
// perf#28 (ONE doorbell): consume the wake fd the server just sent (a dup of its single doorbell) and
// return the canonical process-wide doorbell fd, closing the received dup when one is already held.
int __dserver_ring_doorbell(int fd);
bool __dserver_fd_is_internal(int fd);

int __dserver_get_process_lifetime_pipe(void);
int __dserver_process_lifetime_pipe_refresh(void);
void __dserver_close_process_lifetime_pipe(int fd);

// perf#30 (PROCESS-GLOBAL LANE DIRECTORY): the loader's record array and its capacity. A NULL registry
// means an older loader: the caller must degrade to its per-image behavior, never to a bad pointer.
void* __dserver_ring_lane_registry(void);
int __dserver_ring_lane_slots(void);

CPP_EXTERN_END

#endif // _ELFCALLS_WRAPPER_H
