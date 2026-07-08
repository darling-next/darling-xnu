#ifndef DARLING_XNU_SYSCALL_BSD_IMPL_PSYNCH_RETURN_H
#define DARLING_XNU_SYSCALL_BSD_IMPL_PSYNCH_RETURN_H

#include <stdint.h>

extern long cerror(int __err);

static inline long darling_psynch_wait_error(int error)
{
	return cerror(error);
}

static inline long darling_psynch_wait_return(int result, uint32_t retval)
{
	if (!result)
		return retval;

	/*
	 * Darwin psynch wait errors use the normal syscall error path: the public
	 * wrapper returns -1 and errno carries the full psynch result. For
	 * condvars the high bits may include ECVCLEARED/ECVPREPOST status, so do
	 * not mask to the base errno here; libpthread separates the low-byte errno
	 * from psynch status bits.
	 */
	return darling_psynch_wait_error(result);
}

#endif
