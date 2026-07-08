#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <xnu_syscall/bsd/impl/psynch/psynch_return.h>

static int captured_error;

long cerror(int error)
{
	captured_error = error;
	return -1;
}

static int expect_long(const char* what, long got, long want)
{
	if (got == want)
		return 0;
	fprintf(stderr, "%s: got %ld want %ld\n", what, got, want);
	return 1;
}

static int expect_int(const char* what, int got, int want)
{
	if (got == want)
		return 0;
	fprintf(stderr, "%s: got %d want %d\n", what, got, want);
	return 1;
}

int main(void)
{
	const uint32_t updateval = 0x12345678u;
	const int augmented_eintr = EINTR | 0x200;

	captured_error = 0;
	if (expect_long("success return", darling_psynch_wait_return(0, updateval), updateval))
		return 1;
	if (expect_int("success cerror untouched", captured_error, 0))
		return 1;

	captured_error = 0;
	if (expect_long("augmented error return", darling_psynch_wait_return(augmented_eintr, updateval), -1))
		return 1;
	if (expect_int("augmented error preserved", captured_error, augmented_eintr))
		return 1;

	captured_error = 0;
	if (expect_long("transport EINTR return", darling_psynch_wait_error(EINTR), -1))
		return 1;
	if (expect_int("transport EINTR captured", captured_error, EINTR))
		return 1;

	puts("PSYNCH_RETURN_CONTRACT_OK");
	return 0;
}
