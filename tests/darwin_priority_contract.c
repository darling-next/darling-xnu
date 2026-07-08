#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

typedef int id_t;
#define PRIO_DARWIN_THREAD 3
#define PRIO_DARWIN_PROCESS 4
#define PRIO_DARWIN_BG 0x1000
#define PRIO_DARWIN_NONUI 0x1001
#define __NR_getpriority 140
#define __NR_setpriority 141

static int linux_getpriority_calls;
static int linux_setpriority_calls;

long fake_linux_syscall(long nr, ...)
{
	va_list ap;
	va_start(ap, nr);
	va_end(ap);
	if (nr == __NR_getpriority)
	{
		linux_getpriority_calls++;
		return 42;
	}
	if (nr == __NR_setpriority)
	{
		linux_setpriority_calls++;
		return 24;
	}
	fprintf(stderr, "unexpected syscall %ld\n", nr);
	return -999;
}

#define LINUX_SYSCALL(nr, ...) fake_linux_syscall((nr), ##__VA_ARGS__)

#include "getpriority.c"
#include "setpriority.c"

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
	if (expect(sys_getpriority(PRIO_DARWIN_THREAD, 0) == 0, "thread getpriority should be accepted")) return 1;
	if (expect(sys_getpriority(PRIO_DARWIN_THREAD, 7) == -EINVAL, "thread getpriority nonzero who should fail")) return 1;
	if (expect(sys_getpriority(PRIO_DARWIN_PROCESS, 99) == 0, "process getpriority should be accepted")) return 1;
	if (expect(linux_getpriority_calls == 0, "Darwin getpriority classes must not reach Linux syscall")) return 1;

	if (expect(sys_setpriority(PRIO_DARWIN_THREAD, 0, 0) == 0, "thread priority 0 should be accepted")) return 1;
	if (expect(sys_setpriority(PRIO_DARWIN_THREAD, 0, PRIO_DARWIN_BG) == 0, "thread BG should be accepted")) return 1;
	if (expect(sys_setpriority(PRIO_DARWIN_THREAD, 0, PRIO_DARWIN_NONUI) == 0, "thread NONUI should be accepted")) return 1;
	if (expect(sys_setpriority(PRIO_DARWIN_THREAD, 1, 0) == -EINVAL, "thread nonzero who should fail")) return 1;
	if (expect(sys_setpriority(PRIO_DARWIN_THREAD, 0, 123) == -EINVAL, "thread unknown priority should fail")) return 1;
	if (expect(sys_setpriority(PRIO_DARWIN_PROCESS, 3, PRIO_DARWIN_BG) == 0, "process BG should be accepted")) return 1;
	if (expect(sys_setpriority(PRIO_DARWIN_PROCESS, 3, 123) == -EINVAL, "process unknown priority should fail")) return 1;
	if (expect(linux_setpriority_calls == 0, "Darwin setpriority classes must not reach Linux syscall")) return 1;

	if (expect(sys_getpriority(0, 0) == 42, "non-Darwin getpriority should pass through")) return 1;
	if (expect(sys_setpriority(0, 0, 0) == 24, "non-Darwin setpriority should pass through")) return 1;
	if (expect(linux_getpriority_calls == 1, "getpriority pass-through count")) return 1;
	if (expect(linux_setpriority_calls == 1, "setpriority pass-through count")) return 1;
	return 0;
}
