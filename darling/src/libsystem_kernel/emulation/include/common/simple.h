#ifndef LINUX_DEBUG_H
#define LINUX_DEBUG_H

#include <stdarg.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>

// everything in this header can be used outside of libsystem_kernel

CPP_EXTERN_BEGIN

void __simple_printf(const char* format, ...) __attribute__((format(printf, 1, 2)));
void __simple_kprintf(const char* format, ...) __attribute__((format(printf, 1, 2)));
void __simple_fprintf(int fd, const char* format, ...) __attribute__((format(printf, 2, 3)));
int __simple_sprintf(char *buffer, const char* format, ...) __attribute__((format(printf, 2, 3)));
int __simple_strlen(const char* str);
int __simple_vsprintf(char* buf, const char* format, va_list vl) __attribute__((format(printf, 2, 0)));
int __simple_vsnprintf(char* buffer, size_t max_length, const char* format, va_list args) __attribute__((format(printf, 3, 0)));
int __simple_snprintf(char* buffer, size_t max_length, const char* format, ...) __attribute__((format(printf, 3, 4)));
void __simple_vprintf(const char* format, va_list args) __attribute__((format(printf, 1, 0)));
void __simple_vkprintf(const char* format, va_list args) __attribute__((format(printf, 1, 0)));
void __simple_vfprintf(int fd, const char* format, va_list args) __attribute__((format(printf, 2, 0)));

unsigned long long __simple_atoi(const char* str, const char** endp);
unsigned long long __simple_atoi16(const char* str, const char** endp);

// perf #9-decompose follow-on (dar-dar6x4-perf-5dq): hot-path kprintf gate.
// __simple_kprintf is a SYNCHRONOUS RPC round-trip to darlingserver (send + a ~100us
// recvmsg reply-wait). The guest per-callnum reply-wait breakdown showed unconditional
// debug traces on hot paths (every exec, a hot ioctl, sigexc init) made kprintf 14.5% of
// a clean build's total reply-wait -- pure noise paid for on every build. Such traces
// must use hotpath_kdebug(...) instead of __simple_kprintf(...): it compiles to NOTHING
// by default (no RPC, no sleep) and restores the trace only when the image is built with
// -DDARLING_HOTPATH_KPRINTF_DEBUG. (Genuine error/diagnostic kprintf -- failures, guard
// violations -- stay as __simple_kprintf; only remove cost from traces that fire on the
// success hot path.) The do{}while(0) keeps it a statement and still type-checks the
// args (so format mistakes are caught) even when compiled out.
#ifdef DARLING_HOTPATH_KPRINTF_DEBUG
	#define hotpath_kdebug(...) __simple_kprintf(__VA_ARGS__)
#else
	#define hotpath_kdebug(...) do { if (0) __simple_kprintf(__VA_ARGS__); } while (0)
#endif

// TODO: Remove this in favor of readline in readline.c?
struct simple_readline_buf
{
	char buf[512];
	int used;
};
void __simple_readline_init(struct simple_readline_buf* buf);
char* __simple_readline(int fd, struct simple_readline_buf* buf, char* out, int max_out);

__attribute__((noreturn))
void __simple_abort(void);

CPP_EXTERN_END

#endif // LINUX_DEBUG_H
