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

int main(void)
{
	enum { NFDS = 96 };
	uint32_t bsd[bsd_fdset_words(NFDS)];
	unsigned long linux_words[linux_fdset_words(NFDS)];
	uint32_t roundtrip[bsd_fdset_words(NFDS)];
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

	return 0;
}
