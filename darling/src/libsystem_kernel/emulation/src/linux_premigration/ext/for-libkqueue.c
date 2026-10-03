#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/linux_premigration/resources/dserver-ring.h>
#include <darlingserver/rpc-supplement.h>
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>

#include <darlingserver/rpc.h>

int _dserver_rpc_kqchan_mach_port_open_4libkqueue(uint32_t port_name, void* receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, int* out_socket) {
	// perf#30 (directive section 16): descriptor-bearing early call -> the PROCESS MANAGEMENT PLANE for the
	// semantics and the process COURIER for the returned descriptor, with the token published in
	// reply_payload[1]. -1 from the plane means "not published / not completed": fall back to the datagram,
	// which is safe because nothing was committed.
	{
		/* A SUCCESS THAT DELIVERED NO DESCRIPTOR IS NOT A SUCCESS (dar-4cp9). MEASURED residual boot failure:
		 * [kqchan-plane] status=0 token=<n> fd=-1 out=0 -- the plane answered, the token existed, the courier
		 * receive failed, and this wrapper still returned success with *out_socket unset, so launchd went on
		 * without its channel and the boot stalled in silence (no denial, no signal, no server-side process).
		 * The transfer is retried a bounded number of times -- a fresh plane request is a fresh transaction
		 * because the map is keyed by (pid, seq) -- and if the descriptor still does not arrive the call now
		 * reports failure instead of claiming a channel that does not exist. A non-zero status is a real
		 * answer and is returned unchanged; only the success-without-descriptor case is retried. */
		int planeStatus = -1;
		for (int transferAttempt = 0; transferAttempt < 3; ++transferAttempt) {
			uint64_t reply1 = 0;
			int resolved = -1;
			planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_KQCHAN_MACH_PORT_OPEN,
				(uint64_t)port_name, (uint64_t)(uintptr_t)receive_buffer, receive_buffer_size,
				saved_filter_flags, 0, &reply1);
			if (planeStatus == -1) {
				break;
			}
			if (planeStatus == 0 && reply1 != 0) {
				resolved = __dserver_fd_courier_receive(reply1);
				if (resolved >= 0) {
					*out_socket = resolved;
				}
			}
			// perf#30 (doc section 93): name what the plane route actually produced, bounded and gated. The
			// boot stops right after this call's descriptor is delivered, so this is the line that says
			// whether the guest got a usable descriptor and what it is about to return.
			{
				static int reported = 0;
				if (!reported) {
					reported = 1;
					__simple_fprintf(2, "[kqchan-plane] status=%d token=%llu fd=%d out=%d\n",
						planeStatus, (unsigned long long)reply1, resolved,
						*out_socket);
				}
			}
			if (resolved >= 0) {
				return planeStatus;
			}
			if (planeStatus != 0) {
				return planeStatus;
			}
		}
		if (planeStatus == 0) {
			__simple_fprintf(2, "[kqchan-plane] descriptor-not-delivered after bounded retries; failing the call\n");
			return -LINUX_EIO;
		}
		if (planeStatus != -1) {
			return planeStatus;
		}
	}
	return dserver_rpc_kqchan_mach_port_open(port_name, receive_buffer, receive_buffer_size, saved_filter_flags, out_socket);
};

int _dserver_rpc_kqchan_proc_open_4libkqueue(int32_t pid, uint32_t flags, int* out_socket) {
	// perf#30 (directive sections 16-17, doc section 206): descriptor-bearing early call -> the process MANAGEMENT
	// PLANE for the semantics and the process COURIER for the returned descriptor, exactly as
	// KQCHAN_MACH_PORT_OPEN (9u) and CONSOLE_OPEN (26u) do. The token is published in reply_payload[1] and resolved
	// with the courier receive. MEASURED: the hard oracle denied this call at the outer generated wrapper, which
	// asked for a per-thread socket before any lane could be attempted. -1 from the plane means nothing was
	// published, so the datagram fallback below is safe.
	{
		uint64_t reply1 = 0;
		int planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_KQCHAN_PROC_OPEN,
			(uint64_t)(uint32_t)pid, (uint64_t)flags, 0, 0, 0, &reply1);
		if (planeStatus != -1) {
			if (planeStatus == 0 && reply1 != 0) {
				int resolved = __dserver_fd_courier_receive(reply1);
				if (resolved >= 0) {
					*out_socket = resolved;
				}
			}
			return planeStatus;
		}
	}
	return dserver_rpc_kqchan_proc_open(pid, flags, out_socket);
};

int _dup_4libkqueue(int fd) {
	int ret;

	ret = LINUX_SYSCALL1(__NR_dup, fd);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
};
