#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>

/* A controlled syscall boundary, not a replacement ring implementation. The
 * peer consumes and publishes using the paired server's actual SPSC helpers. */
static long peer_syscall(long number);
#define LINUX_SYSCALL(number, ...) peer_syscall(number)
#define LINUX_SYSCALL0(number) peer_syscall(number)
#define LINUX_SYSCALL1(number, ...) peer_syscall(number)
#define LINUX_SYSCALL2(number, ...) peer_syscall(number)
#define __simple_fprintf(fd, ...) fprintf(stderr, __VA_ARGS__)
#define DARLING_RING_TRANSPORT 1
#define DARLING_GUEST_RECVSPIN 0
#include "dserver-ring.c"
#include <darling/emulation/xnu_syscall/mach/impl/cached_self_ports.h>

typedef uint32_t mach_port_name_t;
#define MACH_PORT_NULL 0
static cached_self_port_t __task_self_port_cache = { CACHED_MACH_PORT_NULL };
#include "mach-callers.inc"

enum response { GOOD, WRONG_SEQ, WRONG_CALL, WRONG_SIZE, NO_REPLY, NEGATIVE_ERROR };
static enum response response;
static unsigned published, uds_calls;
static gr_lane_t *lane;
static uint32_t reply_port = 0x123;

/* These are the alternative UDS side effects. Replaying after publication is
 * observable even if the caller otherwise happens to return a plausible port. */
int dserver_rpc_mach_reply_port(uint32_t *port) { ++uds_calls; *port = reply_port; return 0; }
int dserver_rpc_thread_self_trap(uint32_t *port) { ++uds_calls; *port = reply_port; return 0; }
int dserver_rpc_host_self_trap(uint32_t *port) { ++uds_calls; *port = reply_port; return 0; }
int dserver_rpc_task_self_trap(uint32_t *port) { ++uds_calls; *port = reply_port; return 0; }
int dserver_rpc_ring_attach(int fd, uint64_t size, uint32_t *reason, int *wake_fd) {
    (void)fd; (void)size; (void)reason; (void)wake_fd;
    abort(); /* Setup provides an attached lane; fallback setup denies memfd_create. */
}

static long peer_syscall(long number) {
    if (number == __NR_gettid || number == __NR_getpid) return 42;
    if (number == __NR_futex) return -EINTR; /* exhaust the production wait guard */
    if (number != __NR_write) return -ENOSYS;
    dserver_ring_slot_t *request = dserver_ring_consumer_begin(gr_c2s(lane), GR_SLOT_SIZE, GR_SLOT_COUNT);
    assert(request != NULL);
    ++published;
    if (response != NO_REPLY) {
        dserver_ring_slot_t *reply = dserver_ring_producer_begin(gr_s2c(lane), GR_SLOT_SIZE, GR_SLOT_COUNT);
        assert(reply != NULL);
        reply->seq = request->seq + (response == WRONG_SEQ);
        reply->callnum = request->callnum + (response == WRONG_CALL);
        size_t size = sizeof(uint32_t);
        if (request->callnum == dserver_callnum_uidgid || request->callnum == dserver_callnum_mldr_path ||
            request->callnum == dserver_callnum_vchroot_path) size = 8;
        if (request->callnum == dserver_callnum_started_suspended ||
            request->callnum == dserver_callnum_task_is_64_bit) size = sizeof(bool);
        if (request->callnum == dserver_callnum_set_thread_handles ||
            request->callnum == dserver_callnum_mach_port_allocate) size = 0;
        reply->length = sizeof(dserver_ring_reply_hdr_t) + size + (response == WRONG_SIZE);
        dserver_ring_reply_hdr_t *header = (void *)((char *)reply + sizeof(*reply));
        header->code = response == NEGATIVE_ERROR ? -EIO : 0;
        memset(header + 1, 0, size);
        if (size == sizeof(uint32_t)) memcpy(header + 1, &reply_port, sizeof(reply_port));
        dserver_ring_producer_publish(gr_s2c(lane));
    }
    dserver_ring_consumer_advance(gr_c2s(lane));
    return sizeof(uint64_t);
}

static void setup(enum response mode) {
    if (lane) free(lane->map);
    memset(g_lanes, 0, sizeof(g_lanes));
    lane = &g_lanes[0];
    uint64_t span = sizeof(dserver_ring_t) + GR_SLOT_COUNT * GR_SLOT_SIZE;
    uint64_t c2s = (sizeof(dserver_ring_shm_t) + 63u) & ~63ull;
    uint64_t s2c = (c2s + span + 63u) & ~63ull;
    lane->size = (s2c + span + 63u) & ~63ull;
    lane->map = aligned_alloc(64, lane->size);
    assert(lane->map != NULL);
    memset(lane->map, 0, lane->size);
    gr_cb(lane)->c2s_ring_off = c2s;
    gr_cb(lane)->s2c_ring_off = s2c;
    gr_cb(lane)->server_state = DSERVER_RING_SRV_SLEEPING_EPOLL;
    lane->owner_tid = 42;
    lane->active = 1;
    lane->state = 1;
    lane->seq = 1;
    lane->wake_fd = 99;
    response = mode;
    published = uds_calls = 0;
    __darling_reset_cached_self_ports();
}

static void port_callers(void) {
    uint32_t (*callers[])(void) = {
        mach_reply_port_impl, thread_self_trap_impl, host_self_trap_impl, __task_self_trap_rpc,
    };
    for (unsigned i = 0; i < sizeof(callers) / sizeof(callers[0]); ++i) {
        setup(WRONG_SEQ);
        assert(callers[i]() == MACH_PORT_NULL);
        assert(published == 1 && uds_calls == 0);
        setup(GOOD);
        assert(callers[i]() == reply_port);
        assert(published == 1 && uds_calls == 0);
        setup(GOOD);
        lane->state = -1; /* a pre-publication miss must still permit UDS */
        assert(callers[i]() == reply_port);
        assert(published == 0 && uds_calls == 1);
    }
    enum response failures[] = { WRONG_CALL, WRONG_SIZE, NO_REPLY, NEGATIVE_ERROR };
    for (unsigned i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        setup(failures[i]);
        assert(mach_reply_port_impl() == MACH_PORT_NULL);
        assert(published == 1 && uds_calls == 0);
    }
}

static void bsd_completion(void) {
    int code;
    int32_t uid = 91, gid = 92, tracer = 93;
    bool suspended = true, is64 = true;
    uint64_t length = 94;
    setup(NO_REPLY);
    assert(__dserver_ring_uidgid(10, 11, &uid, &gid, &code) == 0);
    assert(code == -EIO && uid == 91 && gid == 92 && published == 1);
    setup(WRONG_SIZE);
    assert(__dserver_ring_started_suspended(&suspended, &code) == 0);
    assert(code == -EIO && suspended && published == 1);
    setup(WRONG_SEQ);
    assert(__dserver_ring_get_tracer(&tracer, &code) == 0);
    assert(code == -EIO && tracer == 93 && published == 1);
    setup(WRONG_CALL);
    assert(__dserver_ring_task_is_64_bit(42, &is64, &code) == 0);
    assert(code == -EIO && is64 && published == 1);
    setup(NO_REPLY);
    assert(__dserver_ring_set_thread_handles(0, 0, &code) == 0);
    assert(code == -EIO && published == 1);
    setup(WRONG_SIZE);
    assert(__dserver_ring_mldr_path(0, 0, &length, &code) == 0);
    assert(code == -EIO && length == 94 && published == 1);
    setup(NEGATIVE_ERROR);
    assert(__dserver_ring_vchroot_path(0, 0, &length, &code) == 0);
    assert(code == -EIO && length == 94 && published == 1);
    setup(GOOD);
    assert(__dserver_ring_uidgid(-1, -1, &uid, &gid, &code) == 0);
    assert(code == 0 && uid == 0 && gid == 0 && published == 1);
    setup(WRONG_SIZE);
    assert(__dserver_ring_mach_port_allocate(1, 1, 0, &code) == 0);
    assert(code == KERN_FAILURE && published == 1); /* Mach remains positive. */
}

int main(void) {
    port_callers();
    bsd_completion();
    free(lane->map);
    puts("RING_COMPLETION_OK: published failures do not replay or expose reply garbage");
    return 0;
}
