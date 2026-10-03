#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/pthread_canceled.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>

#include <darlingserver/rpc.h>
#include <darlingserver/rpc-supplement.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>

/* Diagnostic probe with ATTRIBUTION and with NO syscall of its own.
 *
 * CANCELATION_POINT() is `if (sys_pthread_canceled(0) == 0) return -EINTR;` -- it can only RETURN, so a death
 * inside it is a death inside this function, and only a bisection of it names the step. Counts alone do not do
 * that: 14 entries and 6 returns across several processes say nothing about which one died, hence the identity.
 *
 * The identity must not cost a syscall. An earlier version called gettid (186) inside the probe on this hot
 * path, and the run being measured got SHORTER -- the boot stopped reaching the console at all. A probe that
 * adds an emulated syscall to the code it measures is not a neutral observer; the stack pointer is free,
 * distinct per thread, and stable for the duration of the call.
 *
 * rax uses LINUX numbering: write is 1. See scripts/guest-probe.h -- a wrong number here is silent. */
static void __pc_probe(const char *tag, int digit) {
	char buf[64];
	int n = 0;
	/* The identity must be free AND portable: this dylib is built for x86_64 and i386, and `%rsp` is only
	 * available in 64-bit mode (the i386 pass rejects it). The address of a local buffer is a per-thread,
	 * per-frame value that costs no syscall and no register. */
	/* PER-THREAD identity: the TCB self-pointer. A per-FRAME value (the address of a local buffer, an earlier
	 * version) cannot correlate probes across a call chain -- sys_open and sys_openat_nocancel have different
	 * frames -- so "does this guest reach the syscall layer" was unanswerable by identity. No syscall is added
	 * (a probe that adds one is not a neutral observer) and no TLS runtime is required. */
	unsigned long id = 0;
#if defined(__x86_64__)
	__asm__ volatile("movq %%fs:0, %0" : "=r"(id));
#elif defined(__i386__)
	__asm__ volatile("movl %%gs:0, %0" : "=r"(id));
#else
	id = (unsigned long)(void *)&n;
#endif
	for (const char *c = tag; *c && n < 40; ++c) buf[n++] = *c;
	/* print the VALUE in hex, not a boolean: an earlier form encoded "negative but not -1" as the digit 8,
	 * which hid the actual status (-EINVAL, the normal "no cancellation pending" answer) behind a
	 * classification and made the decisive number unknowable from the log. */
	if (digit != -1) {
		static const char hex[] = "0123456789abcdef";
		char tmp[16];
		int k = 0, i, neg = digit < 0;
		unsigned long v = neg ? (unsigned long)(-digit) : (unsigned long)digit;
		if (v == 0) tmp[k++] = '0';
		while (v > 0 && k < 15) { tmp[k++] = hex[v & 0xf]; v >>= 4; }
		for (i = 0; i < k && n < 40; ++i) buf[n++] = tmp[k - 1 - i];
		buf[n++] = neg ? '-' : '+';
	}
	buf[n++] = ' '; buf[n++] = 's'; buf[n++] = 'p'; buf[n++] = '=';
	{
		static const char hex[] = "0123456789abcdef";
		char tmp[16];
		int k = 0, i;
		unsigned long v = id & 0xfffff;
		if (v == 0) tmp[k++] = '0';
		while (v > 0 && k < 16) { tmp[k++] = hex[v & 0xf]; v >>= 4; }
		for (i = 0; i < k && n < 60; ++i) buf[n++] = tmp[k - 1 - i];
	}
	buf[n++] = ']'; buf[n++] = '\n';
	{
		long rax = 1, rdi = 2, rsi = (long)buf, rdx = n;
		__asm__ volatile("syscall" : "+a"(rax), "+D"(rdi), "+S"(rsi), "+d"(rdx) : : "rcx", "r11", "memory");
	}
}

long sys_pthread_canceled(int action)
{
	__pc_probe("[pc-entry", -1);
	if (action == 0 && !uses_threads()) {
		__pc_probe("[pc-nothreads", -1);
		return -EINVAL;
	}
	__pc_probe("[pc-threads-ok", -1);

	int ret = -1;
	int planeStatus = -1;
	// perf#30 (directive sections 5-7, doc section 109): pthread_canceled gets an EXPLICIT management op
	// with an explicit completion. It is reached before the lane can be relied on (that is why routing it
	// on the lane was MEASURED RED), so the plane -- not the datagram -- is its home. `planeStatus == -1`
	// means "not published / not completed", and only then does the datagram run: a published call is
	// never retried.
	{
		uint64_t reply0 = 0;
		planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_PTHREAD_CANCELED,
			(uint64_t)(uint32_t)action, 0, 0, 0, &reply0, 0);
		__pc_probe("[pc-postplane st=", planeStatus);
		if (planeStatus != -1) {
			// THE COMPLETION STATUS IS THE CALL'S RETURN, exactly as the datagram path uses the reply code
			// (`ret = dserver_rpc_pthread_canceled(action)`). MEASURED: this read the PAYLOAD instead, and
			// the server does not populate a payload for this op -- so a normal -EINVAL answer ("no
			// cancellation pending") became 0, and 0 is precisely the value that makes CANCELATION_POINT
			// return -EINTR. launchd's first console open was therefore reported as INTERRUPTED and the
			// cancellation machinery tore the thread down, which is why the console branch was unreachable
			// and the exit was silent. XNU semantics: 0 = cancel this thread, EINVAL = do not.
			ret = planeStatus;
		}
	}
	if (planeStatus == -1) {
		// BOUNDED PLANE RETRY, THEN A LOCAL ANSWER -- NEVER THE DATAGRAM, BECAUSE UNDER THE HARD SOCKET GATE THE
		// DATAGRAM IS NOT A TRANSPORT. MEASURED (acceptance suite, natural Ring default, require-zero-creations):
		// the plane answered -1 on 2 of 101 calls, each of those fell back to dserver_rpc_pthread_canceled, that
		// call asks for a PER-THREAD socket, and the gate recorded exactly that as denied=1 with
		// call=pthread_canceled image=kernel. The directive requires this call to be serviced directly, so the
		// fallback is gone: a few bounded retries cover the transient case (the plane's single slot is busy), and
		// if the plane still cannot take it the answer is -EINVAL -- XNU's own value for "nothing pending to
		// cancel", which is what CANCELATION_POINT expects in order to continue normally.
		__pc_probe("[pc-plane-retry st=", planeStatus);
		// THE RETRY THE COMMENT BELOW PROMISES, ACTUALLY PERFORMED (dar-b5pe). MEASURED GAP: this branch said a
		// few bounded retries cover the transient case where the plane's single slot is busy, and then performed
		// no retry at all -- it re-tested the same planeStatus and answered -EINVAL. That answer is not neutral:
		// XNU's CANCELATION_POINT reads 0 as "cancel this thread" and EINVAL as "nothing pending", so a spurious
		// -EINVAL on a request that WAS pending tells a thread to continue where it should have been torn down.
		// The retry is bounded and short (four attempts, a quarter millisecond apart, a few milliseconds in the
		// worst case) because it runs inside a cancellation syscall on a thread that is expected to proceed
		// promptly; the local -EINVAL remains the answer once the bound is exhausted, and the datagram remains
		// forbidden under the hard socket gate.
		for (int attempt = 0; attempt < 4 && planeStatus == -1; ++attempt) {
			uint64_t replyRetry = 0;
			planeStatus = __dserver_plane_request_ex(DSERVER_PROCESS_CONTROL_OP_PTHREAD_CANCELED,
				(uint64_t)(uint32_t)action, 0, 0, 0, &replyRetry, 0);
			if (planeStatus != -1) {
				ret = planeStatus;
				break;
			}
			long rts[2] = {0, 250000L};
			(void)LINUX_SYSCALL6(__NR_nanosleep, rts, 0, 0, 0, 0, 0);
		}
		if (planeStatus == -1) {
			__pc_probe("[pc-local-einval", -1);
			ret = -EINVAL;
		}
	}
	__pc_probe("[pc-return-", ret < 0 ? 9 : 0);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
