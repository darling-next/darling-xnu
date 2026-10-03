#include <darling/emulation/conversion/network/recvmsg.h>

#include <darling/emulation/conversion/network/getsockopt.h>

int socket_level_bsd_to_linux(int level)
{
	switch (level)
	{
		case BSD_SOL_SOCKET:
			return LINUX_SOL_SOCKET;
		default:
			return level;
	}
}

int socket_level_linux_to_bsd(int level)
{
	switch (level)
	{
		case LINUX_SOL_SOCKET:
			return BSD_SOL_SOCKET;
		default:
			return level;
	}
}

int socket_cmsg_type_bsd_to_linux(int level, int type)
{
	if (level == XNU_IPPROTO_IP && type == BSD_IP_PKTINFO)
		return LINUX_IP_PKTINFO;
	if (level == XNU_IPPROTO_IPV6) {
		if (type == BSD_IPV6_PKTINFO)
			return LINUX_IPV6_PKTINFO;
		if (type == BSD_IPV6_2292PKTINFO)
			return LINUX_IPV6_2292PKTINFO;
	}
	return type;
}

int socket_cmsg_type_linux_to_bsd(int level, int type)
{
	if (level == XNU_IPPROTO_IP && type == LINUX_IP_PKTINFO)
		return BSD_IP_PKTINFO;
	if (level == XNU_IPPROTO_IPV6) {
		if (type == LINUX_IPV6_PKTINFO)
			return BSD_IPV6_PKTINFO;
		if (type == LINUX_IPV6_2292PKTINFO)
			return BSD_IPV6_2292PKTINFO;
	}
	return type;
}
