#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>

#define IOCTL_PASS 0
#define IOCTL_HANDLED 1
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define SIOCAIFADDR 0x1111
#define SIOCAIFADDR_IN6 0x2222

#include "socket.c"

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
	int retval = 12345;
	struct ifconf ifc;
	memset(&ifc, 0xa5, sizeof(ifc));
	ifc.ifc_len = 777;

	if (expect(handle_socket(-1, 0xC00C6924, &ifc, &retval) == IOCTL_HANDLED,
			"SIOCGIFCONF should be handled")) return 1;
	if (expect(retval == 0, "SIOCGIFCONF retval should be success")) return 1;
	if (expect(ifc.ifc_len == 0, "SIOCGIFCONF should report an empty interface list")) return 1;

	retval = 12345;
	if (expect(handle_socket(-1, 0xC00C6924, NULL, &retval) == IOCTL_HANDLED,
			"SIOCGIFCONF NULL arg should be handled")) return 1;
	if (expect(retval == -EFAULT, "SIOCGIFCONF NULL arg should return -EFAULT")) return 1;

	retval = 12345;
	if (expect(handle_socket(-1, 0x12345678, &ifc, &retval) == IOCTL_PASS,
			"unknown socket ioctl should pass through")) return 1;
	if (expect(retval == 12345, "pass-through ioctl should not modify retval")) return 1;
	return 0;
}
