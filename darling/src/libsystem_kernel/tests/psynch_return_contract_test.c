#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <xnu_syscall/bsd/impl/psynch/psynch_return.h>

static int expect_long(const char* what, long got, long want)
{
	if (got == want)
		return 0;
	fprintf(stderr, "%s: got %ld want %ld\n", what, got, want);
	return 1;
}

int main(void)
{
	const uint32_t updateval = 0x12345678u;
	const int augmented_eintr = EINTR | 0x200;

	if (expect_long("success return", darling_psynch_wait_return(0, updateval), updateval))
		return 1;

	if (expect_long("augmented error return", darling_psynch_wait_return(augmented_eintr, updateval), -augmented_eintr))
		return 1;

	if (expect_long("transport EINTR return", darling_psynch_wait_error(EINTR), -EINTR))
		return 1;

	puts("PSYNCH_RETURN_CONTRACT_OK");
	return 0;
}
