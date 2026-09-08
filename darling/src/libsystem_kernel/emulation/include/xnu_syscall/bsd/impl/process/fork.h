#ifndef LINUX_FORK_H
#define LINUX_FORK_H

long sys_fork(void);
/* Private until exec: failed children require an internal __WCLONE reap. */
long fork_for_spawn(void);

#endif // LINUX_FORK_H
