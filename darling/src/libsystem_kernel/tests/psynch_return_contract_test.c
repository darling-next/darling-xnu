#include <errno.h>
#include <stdint.h>
#include <stdio.h>

long sys_psynch_cvwait(void *cv, uint64_t cvlsgen, uint32_t cvugen,
		void *mutex, uint64_t mugen, uint32_t flags, int64_t sec,
		uint32_t nsec);
long sys_psynch_mutexwait(void *mutex, uint32_t mgen, uint32_t ugen,
		uint64_t tid, uint32_t flags);
long sys_psynch_rw_rdlock(void *rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags);
long sys_psynch_rw_wrlock(void *rwlock, uint32_t lgenval, uint32_t ugenval,
		uint32_t rw_wc, int flags);

static int stub_rpc_ret;
static uint32_t stub_rpc_retval;

int dserver_rpc_psynch_cvwait(void *cv, uint64_t cvlsgen, uint32_t cvugen,
		void *mutex, uint64_t mugen, uint32_t flags, int64_t sec,
		uint32_t nsec, uint32_t *retval)
{
	(void)cv;
	(void)cvlsgen;
	(void)cvugen;
	(void)mutex;
	(void)mugen;
	(void)flags;
	(void)sec;
	(void)nsec;
	*retval = stub_rpc_retval;
	return stub_rpc_ret;
}

int dserver_rpc_psynch_mutexwait(void *mutex, uint32_t mgen, uint32_t ugen,
		uint64_t tid, uint32_t flags, uint32_t *retval)
{
	(void)mutex;
	(void)mgen;
	(void)ugen;
	(void)tid;
	(void)flags;
	*retval = stub_rpc_retval;
	return stub_rpc_ret;
}

int dserver_rpc_psynch_rw_rdlock(void *rwlock, uint32_t lgenval,
		uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval)
{
	(void)rwlock;
	(void)lgenval;
	(void)ugenval;
	(void)rw_wc;
	(void)flags;
	*retval = stub_rpc_retval;
	return stub_rpc_ret;
}

int dserver_rpc_psynch_rw_wrlock(void *rwlock, uint32_t lgenval,
		uint32_t ugenval, uint32_t rw_wc, int flags, uint32_t *retval)
{
	(void)rwlock;
	(void)lgenval;
	(void)ugenval;
	(void)rw_wc;
	(void)flags;
	*retval = stub_rpc_retval;
	return stub_rpc_ret;
}

static int
expect_long(const char *what, long got, long want)
{
	if (got == want)
		return 0;
	fprintf(stderr, "%s: got %ld want %ld\n", what, got, want);
	return 1;
}

static int
expect_wait_contract(const char *what, long (*call)(void))
{
	const uint32_t updateval = 0x12345678u;
	const int augmented_error = ETIMEDOUT | 0x100;

	stub_rpc_ret = 0;
	stub_rpc_retval = updateval;
	if (expect_long(what, call(), updateval))
		return 1;

	stub_rpc_ret = augmented_error;
	stub_rpc_retval = updateval;
	if (expect_long(what, call(), -augmented_error))
		return 1;

	stub_rpc_ret = -4;
	stub_rpc_retval = updateval;
	if (expect_long(what, call(), -EINTR))
		return 1;

	return 0;
}

static long
call_cvwait(void)
{
	return sys_psynch_cvwait(0, 0, 0, 0, 0, 0, 0, 0);
}

static long
call_mutexwait(void)
{
	return sys_psynch_mutexwait(0, 0, 0, 0, 0);
}

static long
call_rw_rdlock(void)
{
	return sys_psynch_rw_rdlock(0, 0, 0, 0, 0);
}

static long
call_rw_wrlock(void)
{
	return sys_psynch_rw_wrlock(0, 0, 0, 0, 0);
}

int
main(void)
{
	if (expect_wait_contract("cvwait", call_cvwait))
		return 1;
	if (expect_wait_contract("mutexwait", call_mutexwait))
		return 1;
	if (expect_wait_contract("rw_rdlock", call_rw_rdlock))
		return 1;
	if (expect_wait_contract("rw_wrlock", call_rw_wrlock))
		return 1;

	puts("PSYNCH_RETURN_CONTRACT_OK");
	return 0;
}
