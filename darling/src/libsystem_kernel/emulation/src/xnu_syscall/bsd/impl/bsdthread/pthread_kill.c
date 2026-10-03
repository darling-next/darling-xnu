#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/pthread_kill.h>

#include <sys/errno.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/common/simple.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc-supplement.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

long sys_pthread_kill(int thread_port, int sig)
{
	// perf#30 REMOVAL STEP 2 (measured): `raise()` in this guest is a pthread_kill to the calling thread and was the
	// last call in the ordinary syscall surface that forced the per-thread RPC socket (`[rpc-socket-DENIED]
	// call=pthread_kill` under the hard hatch). Its home is the MANAGEMENT PLANE: no S2C upcall is required (the
	// ordinary semantics is Thread::sendSignal, a host tgkill), so the direct-servicing plane carries it exactly as it
	// carries pthread_canceled. The completion status IS the call's return; the datagram runs only when the request
	// was not published, and a published request is never retried on another transport.
	int ret = -1;
	int planeStatus = -1;
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_PTHREAD_KILL,
			(uint64_t)(uint32_t)thread_port, (uint64_t)(uint32_t)signum_bsd_to_linux(sig), 0, 0, &reply0, 0);
		if (planeStatus != -1) {
			ret = planeStatus;
		}
	}
	if (planeStatus == -1) {
		ret = dserver_rpc_pthread_kill(thread_port, signum_bsd_to_linux(sig));
	}
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
