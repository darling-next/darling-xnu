// perf #9-decompose (dar-dar6x4-perf-5dq): single shared per-callnum recvmsg-sleep
// accumulator table + the process-exit dump. See rpc-sleep-account.h for the design.
//
// Compiled ONCE into the emulation object library (not via the generated rpc.c, which is
// compiled into two object libraries). The inline begin/end hooks in the header reference
// this table by `extern`, so both rpc.c copies and the exit path all touch the SAME table.
//
// Entire file is empty unless DARLING_RPC_SLEEP_ACCOUNT is defined (diagnostic builds).

#ifdef DARLING_RPC_SLEEP_ACCOUNT

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/resources/rpc-sleep-account.h>

// The single shared accumulators (declared extern in the header). Unit: TSC ticks.
unsigned long __darling_rpc_sleep_count[DARLING_RPC_SLEEP_ACCOUNT_MAX];
unsigned long __darling_rpc_sleep_total_ticks[DARLING_RPC_SLEEP_ACCOUNT_MAX];

#ifndef DARLING_RPC_SLEEP_ACCOUNT_PATH
// Fixed HOST path: raw Linux syscalls hit the host kernel directly, so this is a host
// path, not a guest/vchroot path. Diagnostic-only; the harness truncates it before a run
// and aggregates it after.
#define DARLING_RPC_SLEEP_ACCOUNT_PATH "/tmp/darling-rpc-sleep.log"
#endif

static int __darling_rpc_utoa(unsigned long v, char* buf) {
	char tmp[20];
	int n = 0;
	if (v == 0) { buf[0] = '0'; return 1; }
	while (v > 0) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
	for (int i = 0; i < n; ++i) buf[i] = tmp[n - 1 - i];
	return n;
}

static int __darling_rpc_sleep_dumped;

// Dump the per-process table, once, appended to the host log as
// "<pid> <callnum> <count> <total_ticks>\n" lines (only nonzero rows). Idempotent guard
// so a second call (e.g. exit then _exit) never double-counts. A build forks thousands of
// short guest processes -> thousands of appended dumps -> sum offline by call number.
// Each per-process dump is well under PIPE_BUF, so O_APPEND writes do not interleave.
void __darling_rpc_sleep_dump(void) {
	if (__darling_rpc_sleep_dumped) return;
	__darling_rpc_sleep_dumped = 1;

	int any = 0;
	for (int i = 0; i < DARLING_RPC_SLEEP_ACCOUNT_MAX; ++i) {
		if (__darling_rpc_sleep_count[i]) { any = 1; break; }
	}
	if (!any) return;

	// open(path, O_WRONLY|O_CREAT|O_APPEND, 0644). Linux: O_WRONLY=01, O_CREAT=0100,
	// O_APPEND=02000; AT_FDCWD=-100.
	long fd = LINUX_SYSCALL(__NR_openat, -100, DARLING_RPC_SLEEP_ACCOUNT_PATH,
		01 | 0100 | 02000, 0644);
	if (fd < 0) return;

	char line[80];
	int pid = (int)LINUX_SYSCALL0(__NR_getpid);
	for (int i = 0; i < DARLING_RPC_SLEEP_ACCOUNT_MAX; ++i) {
		if (!__darling_rpc_sleep_count[i]) continue;
		int p = 0;
		p += __darling_rpc_utoa((unsigned long)pid, line + p); line[p++] = ' ';
		p += __darling_rpc_utoa((unsigned long)i, line + p); line[p++] = ' ';
		p += __darling_rpc_utoa(__darling_rpc_sleep_count[i], line + p); line[p++] = ' ';
		p += __darling_rpc_utoa(__darling_rpc_sleep_total_ticks[i], line + p); line[p++] = '\n';
		LINUX_SYSCALL(__NR_write, fd, line, p);
	}
	LINUX_SYSCALL(__NR_close, fd);
}

#endif // DARLING_RPC_SLEEP_ACCOUNT
