#ifndef LINUX_FORK_H
#define LINUX_FORK_H

long sys_fork(void);
/*
 * Private until exec. On success the parent owns a CLOEXEC pidfd and must close
 * it after its internal P_PIDFD/__WCLONE wait; the child does not inherit it.
 * Requires Linux >= 5.4 (CLONE_PIDFD arrived in 5.2, P_PIDFD waits in 5.4).
 */
long fork_for_spawn(int* pidfd);

#endif // LINUX_FORK_H
