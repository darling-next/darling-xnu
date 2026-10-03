#include "fstatfs_missing_proc_stubs.h"

static inline void __simple_readline_init(struct simple_readline_buf* buf)
{
	(void)buf;
}

static inline int __simple_readline(int fd, struct simple_readline_buf* buf, char* line, unsigned long line_size)
{
	(void)fd;
	(void)buf;
	(void)line;
	(void)line_size;
	return 0;
}
