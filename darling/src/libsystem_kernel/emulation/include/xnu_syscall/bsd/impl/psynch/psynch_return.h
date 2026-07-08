#ifndef DARLING_XNU_SYSCALL_BSD_IMPL_PSYNCH_RETURN_H
#define DARLING_XNU_SYSCALL_BSD_IMPL_PSYNCH_RETURN_H

#include <stdint.h>

static inline long darling_psynch_wait_error(int error)
{
	return -error;
}

static inline long darling_psynch_wait_return(int result, uint32_t retval)
{
	if (!result)
		return retval;

	/*
	 * Darling's BSD syscall implementation returns negative errno values to
	 * the generated public syscall wrapper, which then routes them through
	 * cerror. Preserve the full psynch result here: condvars may include
	 * ECVCLEARED/ECVPREPOST status bits above the low-byte errno, and
	 * libpthread decodes those bits after cerror stores them in errno.
	 */
	return darling_psynch_wait_error(result);
}

#endif
