#ifndef LINUX_BSD_IMPL_SELECT_FDSET_H
#define LINUX_BSD_IMPL_SELECT_FDSET_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BSD_FDSET_BITS_PER_WORD 32
#define LINUX_FDSET_BITS_PER_WORD (sizeof(unsigned long) * 8)
#define DARWIN_FD_SETSIZE 1024

#define DARWIN_FDSET_LINUX_WORDS \
	((DARWIN_FD_SETSIZE + LINUX_FDSET_BITS_PER_WORD - 1) / LINUX_FDSET_BITS_PER_WORD)

typedef struct {
	void* bsd_set;
	unsigned long linux_set[DARWIN_FDSET_LINUX_WORDS];
} darwin_fdset_adapter_t;

static inline int darwin_fdset_validate_nfds(int nfds)
{
	if (nfds < 0 || nfds > DARWIN_FD_SETSIZE)
		return -EINVAL;

	return 0;
}

static inline size_t bsd_fdset_words(int nfds) {
	return (nfds <= 0) ? 0 : (((size_t)nfds + BSD_FDSET_BITS_PER_WORD - 1) / BSD_FDSET_BITS_PER_WORD);
}

static inline size_t linux_fdset_words(int nfds) {
	return (nfds <= 0) ? 0 : (((size_t)nfds + LINUX_FDSET_BITS_PER_WORD - 1) / LINUX_FDSET_BITS_PER_WORD);
}

static inline int bsd_fdset_isset(const uint32_t* set, int fd) {
	return (set[fd / BSD_FDSET_BITS_PER_WORD] & ((uint32_t)1 << (fd % BSD_FDSET_BITS_PER_WORD))) != 0;
}

static inline void bsd_fdset_set(uint32_t* set, int fd) {
	set[fd / BSD_FDSET_BITS_PER_WORD] |= (uint32_t)1 << (fd % BSD_FDSET_BITS_PER_WORD);
}

static inline int linux_fdset_isset(const unsigned long* set, int fd) {
	return (set[fd / LINUX_FDSET_BITS_PER_WORD] & (1UL << (fd % LINUX_FDSET_BITS_PER_WORD))) != 0;
}

static inline void linux_fdset_set(unsigned long* set, int fd) {
	set[fd / LINUX_FDSET_BITS_PER_WORD] |= 1UL << (fd % LINUX_FDSET_BITS_PER_WORD);
}

static inline unsigned long* darwin_fdset_linux_ptr(darwin_fdset_adapter_t* adapter)
{
	return adapter->bsd_set ? adapter->linux_set : NULL;
}

static inline void bsd_fdset_to_linux(int nfds, const void* bsd_set, unsigned long* linux_set) {
	const uint32_t* bsd_words = bsd_set;

	if (bsd_set == NULL)
		return;

	memset(linux_set, 0, linux_fdset_words(nfds) * sizeof(*linux_set));

	for (int fd = 0; fd < nfds; fd++) {
		if (bsd_fdset_isset(bsd_words, fd))
			linux_fdset_set(linux_set, fd);
	}
}

static inline void linux_fdset_to_bsd(int nfds, const unsigned long* linux_set, void* bsd_set) {
	uint32_t* bsd_words = bsd_set;
	size_t bytes = bsd_fdset_words(nfds) * sizeof(*bsd_words);

	if (bsd_set == NULL)
		return;

	memset(bsd_words, 0, bytes);

	for (int fd = 0; fd < nfds; fd++) {
		if (linux_fdset_isset(linux_set, fd))
			bsd_fdset_set(bsd_words, fd);
	}
}

static inline void darwin_fdset_prepare(darwin_fdset_adapter_t* adapter, int nfds, void* bsd_set)
{
	adapter->bsd_set = bsd_set;
	bsd_fdset_to_linux(nfds, bsd_set, adapter->linux_set);
}

static inline void darwin_fdset_copyback(const darwin_fdset_adapter_t* adapter, int nfds)
{
	linux_fdset_to_bsd(nfds, adapter->linux_set, adapter->bsd_set);
}

#endif
