#ifndef LINUX_PSELECT_H
#define LINUX_PSELECT_H

#include <time.h>

#include <darling/emulation/conversion/signal/duct_signals.h>

long sys_pselect(int nfds, void* rfds, void* wfds, void* efds, const struct timespec* timeout, const sigset_t* mask);
long sys_pselect_nocancel(int nfds, void* rfds, void* wfds, void* efds, const struct timespec* timeout, const sigset_t* mask);

#endif // LINUX_PSELECT_H
