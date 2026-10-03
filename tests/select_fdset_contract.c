#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fdset.h"

static int expect(int condition, const char* message)
{
	if (!condition)
	{
		fprintf(stderr, "%s\n", message);
		return 1;
	}
	return 0;
}

static int
check_validation(void)
{
	if (expect(darwin_fdset_validate_nfds(-1) == -EINVAL,
				"negative nfds must fail"))
		return 1;
	if (expect(darwin_fdset_validate_nfds(0) == 0,
				"zero nfds must pass"))
		return 1;
	if (expect(darwin_fdset_validate_nfds(DARWIN_FD_SETSIZE) == 0,
				"FD_SETSIZE nfds must pass"))
		return 1;
	if (expect(darwin_fdset_validate_nfds(DARWIN_FD_SETSIZE + 1) == -EINVAL,
				"oversized nfds must fail"))
		return 1;
	return 0;
}

static int
check_null_set(void)
{
	darwin_fdset_adapter_t adapter;

	memset(&adapter, 0xa5, sizeof(adapter));
	darwin_fdset_prepare(&adapter, 64, NULL);
	if (expect(darwin_fdset_linux_ptr(&adapter) == NULL,
				"NULL BSD set must stay NULL for Linux"))
		return 1;
	darwin_fdset_copyback(&adapter, 64);
	return 0;
}

int main(void)
{
	enum { NFDS = 96 };
	uint32_t bsd[bsd_fdset_words(NFDS)];
	unsigned long linux_words[linux_fdset_words(NFDS)];
	uint32_t roundtrip[bsd_fdset_words(NFDS)];
	darwin_fdset_adapter_t adapter;

	if (check_validation()) return 1;
	if (check_null_set()) return 1;

	memset(bsd, 0, sizeof(bsd));
	memset(linux_words, 0xa5, sizeof(linux_words));
	memset(roundtrip, 0xa5, sizeof(roundtrip));

	bsd_fdset_set(bsd, 1);
	bsd_fdset_set(bsd, 33);
	bsd_fdset_set(bsd, 63);
	bsd_fdset_set(bsd, 64);
	bsd_fdset_set(bsd, 95);

	bsd_fdset_to_linux(NFDS, bsd, linux_words);
	if (expect(linux_fdset_isset(linux_words, 1), "lost fd 1 in BSD->Linux")) return 1;
	if (expect(linux_fdset_isset(linux_words, 33), "lost fd 33 in BSD->Linux")) return 1;
	if (expect(linux_fdset_isset(linux_words, 63), "lost fd 63 in BSD->Linux")) return 1;
	if (expect(linux_fdset_isset(linux_words, 64), "lost fd 64 in BSD->Linux")) return 1;
	if (expect(linux_fdset_isset(linux_words, 95), "lost fd 95 in BSD->Linux")) return 1;
	if (expect(!linux_fdset_isset(linux_words, 32), "spurious fd 32 in BSD->Linux")) return 1;
	if (expect(!linux_fdset_isset(linux_words, 65), "spurious fd 65 in BSD->Linux")) return 1;

	linux_fdset_to_bsd(NFDS, linux_words, roundtrip);
	for (int fd = 0; fd < NFDS; fd++)
	{
		if (bsd_fdset_isset(bsd, fd) != bsd_fdset_isset(roundtrip, fd))
		{
			fprintf(stderr, "roundtrip mismatch at fd %d\n", fd);
			return 1;
		}
	}

	memset(roundtrip, 0xa5, sizeof(roundtrip));
	darwin_fdset_prepare(&adapter, NFDS, bsd);
	if (expect(darwin_fdset_linux_ptr(&adapter) == adapter.linux_set,
				"non-NULL BSD set must produce Linux set"))
		return 1;
	memset(bsd, 0, sizeof(bsd));
	memset(adapter.linux_set, 0, sizeof(adapter.linux_set));
	linux_fdset_set(adapter.linux_set, 64);
	darwin_fdset_copyback(&adapter, NFDS);
	if (expect(bsd_fdset_isset(bsd, 64), "adapter copyback lost fd 64"))
		return 1;
	if (expect(!bsd_fdset_isset(bsd, 63), "adapter copyback kept stale fd 63"))
		return 1;

	return 0;
}
