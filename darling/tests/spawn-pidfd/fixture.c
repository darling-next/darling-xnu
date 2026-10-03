#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>
#include <darling/emulation/xnu_syscall/bsd/impl/process/posix_spawn.h>

/* Host adapters for Darwin-only runtime services, not for fork/spawn logic. */
#define LINUX_SIGCHLD SIGCHLD
#define LINUX_O_CLOEXEC O_CLOEXEC
#define LINUX_O_RDONLY O_RDONLY
#define LINUX_O_DIRECTORY O_DIRECTORY
#define POSIX_SPAWN_RESETIDS 0x01
#define POSIX_SPAWN_SETPGROUP 0x02
#define POSIX_SPAWN_SETSIGMASK 0x08
#define POSIX_SPAWN_SETEXEC 0x40
#define POSIX_SPAWN_START_SUSPENDED 0x80
#define POSIX_SPAWN_CLOEXEC_DEFAULT 0x4000
struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};
typedef struct {
    void (*posix_spawn_prepare)(void);
    void (*posix_spawn_parent)(void);
    void (*posix_spawn_child)(void);
} * _libkernel_functions_t;
typedef struct { void (*close)(int); } guard_entry_options_t;
enum { guard_flag_prevent_close = 1, guard_flag_close_on_fork = 2 };
static void guard_table_postfork_child(void) {}
static int guard_table_add(int fd, int flags, guard_entry_options_t* options) { return 0; }
static int guard_table_check(int fd, int flags) { return 0; }
static int get_perthread_wd(void) { return -1; }
static void __mldr_prefork_prepare(void) {}
static void __mldr_postfork_parent(void) {}
static void __mldr_postfork_child(void) {}
static int __dserver_process_lifetime_pipe_refresh(void) { return -1; }
static void __dserver_close_socket(int fd) {}
static void __dserver_close_process_lifetime_pipe(int fd) {}
static int __dserver_process_socket(void) { return -1; }
static int __dserver_get_process_lifetime_pipe(void) { return -1; }
static int dserver_rpc_checkin(bool child, void* stack, int fd) { return 0; }
static int dserver_rpc_stop_after_exec(void) { return 0; }
#define __simple_printf printf
#define __simple_sprintf sprintf
#define __simple_abort abort
#define __simple_atoi(str, end) ((int)strtol(str, end, 10))
static int errno_linux_to_bsd(int value) { return value; }
static long converted(long value) { return value < 0 ? -errno : value; }
static long close_internal(int fd) { return converted(close(fd)); }
static long sys_fchdir(int fd) { return converted(fchdir(fd)); }
static long sys_chdir(const char* path) { return converted(chdir(path)); }
static long sys_open(const char* path, int flags, int mode) { return converted(open(path, flags, mode)); }
static long sys_dup(int fd) { return converted(dup(fd)); }
static long sys_dup2(int oldfd, int newfd) { return converted(dup2(oldfd, newfd)); }
static long sys_fcntl(int fd, int cmd, long arg) { return converted(fcntl(fd, cmd, arg)); }
static long sys_setpgid(int pid, int group) { return converted(setpgid(pid, group)); }
static long sys_getgid(void) { return getgid(); }
static long sys_getuid(void) { return getuid(); }
static long sys_setgid(int gid) { return converted(setgid(gid)); }
static long sys_setuid(int uid) { return converted(setuid(uid)); }
static long sys_sigprocmask(int how, const unsigned int* mask, void* old) {
    sigset_t set;
    sigemptyset(&set);
    for (int sig = 1; sig <= 32; ++sig)
        if (*mask & (1U << (sig - 1))) sigaddset(&set, sig);
    return converted(sigprocmask(SIG_SETMASK, &set, old));
}

enum scenario { NORMAL, PRIVATE_DEATH, READ_INTERRUPT, WAIT_INTERRUPT, CLONE_FAILURE, REAP_FIRST };
static enum scenario scenario;
static pid_t original_pid, replacement_pid;
static volatile sig_atomic_t application_pid, application_status, alarms;
static int clone_calls, read_interrupts, wait_interrupts, reuse;
static int original_pidfd = -1;
static void noop(void) {}
static void child_hook(void) {
    if (scenario == PRIVATE_DEATH) {
        kill(getpid(), SIGKILL);
        _exit(99);
    }
    if (scenario == READ_INTERRUPT) usleep(100000);
}
static struct {
    void (*posix_spawn_prepare)(void);
    void (*posix_spawn_parent)(void);
    void (*posix_spawn_child)(void);
} callbacks = { noop, noop, child_hook };
_libkernel_functions_t _libkernel_functions = (void*)&callbacks;
static long sys_execve(char* path, char** argv, char** env) {
    return converted(execve(path, argv, env));
}
static long sys_read(int fd, void* data, size_t size) {
    if (scenario == READ_INTERRUPT && !read_interrupts) ualarm(10000, 0);
    long result = converted(read(fd, data, size));
    if (result == -EINTR) ++read_interrupts;
    return result;
}
static long sys_write(int fd, const void* data, size_t size) {
    long result = converted(write(fd, data, size));
    if (scenario == WAIT_INTERRUPT) usleep(100000);
    return result;
}
static void sys_exit(int status) { _exit(status); }
static void alarm_handler(int sig) { ++alarms; }
static void application_handler(int sig) {
    int saved = errno, status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        application_pid = pid;
        application_status = status;
    }
    errno = saved;
}
static void schedule_reuse(void) {
    /* Pause the production internal wait until the application has reaped exec. */
    while (application_pid != original_pid) usleep(1000);
    if (!reuse) return;
    /* run.py enforces a newly-created PID namespace before enabling this mode. */
    int fd = open("/proc/sys/kernel/ns_last_pid", O_WRONLY | O_CLOEXEC);
    if (fd < 0) { perror("private namespace ns_last_pid"); exit(1); }
    char value[32];
    int length = snprintf(value, sizeof(value), "%d", original_pid - 1);
    assert(write(fd, value, length) == length);
    assert(close(fd) == 0);
    replacement_pid = syscall(SYS_clone, 0, 0, 0, 0, 0);
    assert(replacement_pid >= 0);
    if (replacement_pid == 0) _exit(42);
    assert(replacement_pid == original_pid);
}
long linux_syscall(long a1, long a2, long a3, long a4, long a5, long a6, int nr) {
    if (nr == SYS_clone || nr == SYS_fork) {
        ++clone_calls;
        struct rlimit saved;
        if (scenario == CLONE_FAILURE) {
            assert(getrlimit(RLIMIT_NOFILE, &saved) == 0);
            struct rlimit exhausted = saved;
            exhausted.rlim_cur = 0;
            assert(setrlimit(RLIMIT_NOFILE, &exhausted) == 0);
        }
        long result = converted(syscall(nr, a1, a2, a3, a4, a5, a6));
        if (scenario == CLONE_FAILURE) assert(setrlimit(RLIMIT_NOFILE, &saved) == 0);
        if (result > 0) {
            original_pid = result;
            if (nr == SYS_clone && (a1 & 0x1000)) {
                original_pidfd = *(int*)a3;
                assert(fcntl(original_pidfd, F_GETFD) & FD_CLOEXEC);
            }
        }
        return result;
    }
    if (nr == SYS_waitid || nr == SYS_wait4) {
        if (scenario == REAP_FIRST && !replacement_pid) schedule_reuse();
        if (scenario == WAIT_INTERRUPT && !wait_interrupts) ualarm(10000, 0);
        long result = converted(syscall(nr, a1, a2, a3, a4, a5, a6));
        if (result == -EINTR) ++wait_interrupts;
        return result;
    }
    return converted(syscall(nr, a1, a2, a3, a4, a5, a6));
}

/* Compile and execute the actual implementation, not a duplicate algorithm. */
#include "fork.c"
#include "posix_spawn.c"

static int fd_count(void) {
    DIR* dir = opendir("/proc/self/fd");
    assert(dir);
    int count = 0;
    while (readdir(dir)) ++count;
    assert(closedir(dir) == 0);
    return count;
}
static void set_handler(void (*handler)(int)) {
    struct sigaction action = { .sa_handler = handler };
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGCHLD, &action, NULL) == 0);
}
static void assert_closed(void) {
    if (original_pidfd >= 0) {
        errno = 0;
        assert(fcntl(original_pidfd, F_GETFD) == -1 && errno == EBADF);
    }
}
static long spawn_case(enum scenario selected, const char* path, int expected) {
    scenario = selected;
    int before = fd_count(), pid = -123;
    original_pidfd = -1;
    char* args[] = { (char*)path, (char*)"-c", (char*)"exit 7", NULL };
    char* env[] = { NULL };
    long result = sys_posix_spawn(&pid, path, NULL, args, env);
    assert(result == expected);
    assert_closed();
    assert(fd_count() == before);
    if (result == 0) assert(pid == original_pid);
    else assert(pid == -123);
    return pid;
}
int main(int argc, char** argv) {
    reuse = argc == 2 && strcmp(argv[1], "--reuse") == 0;
    alarm(20);
    struct sigaction action = { .sa_handler = alarm_handler };
    sigemptyset(&action.sa_mask);
    assert(sigaction(SIGALRM, &action, NULL) == 0);
    set_handler(SIG_DFL);
    scenario = NORMAL;
    pid_t ordinary = sys_fork();
    assert(ordinary >= 0);
    if (ordinary == 0) _exit(9);
    int status;
    assert(waitpid(ordinary, &status, 0) == ordinary);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 9);
    pid_t pid = spawn_case(NORMAL, "/bin/sh", 0);
    assert(waitpid(pid, &status, 0) == pid);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
    set_handler(application_handler);
    spawn_case(REAP_FIRST, "/bin/sh", 0);
    assert(application_pid == original_pid);
    assert(WIFEXITED(application_status) && WEXITSTATUS(application_status) == 7);
    if (reuse) {
        assert(waitpid(replacement_pid, &status, __WCLONE) == replacement_pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 42);
    }
    application_pid = 0;
    application_status = 0;
    spawn_case(NORMAL, "/definitely-missing-spawn-pidfd", -ENOENT);
    spawn_case(PRIVATE_DEATH, "/bin/sh", -EIO);
    spawn_case(READ_INTERRUPT, "/definitely-missing-spawn-pidfd", -ENOENT);
    assert(read_interrupts > 0);
    spawn_case(WAIT_INTERRUPT, "/definitely-missing-spawn-pidfd", -ENOENT);
    assert(wait_interrupts > 0 && alarms >= 2);
    spawn_case(CLONE_FAILURE, "/bin/sh", -EMFILE);
    assert(application_pid == 0);
    errno = 0;
    assert(waitpid(-1, &status, __WCLONE | WNOHANG) == -1 && errno == ECHILD);
    struct xnu__posix_spawnattr attr = { .psa_flags = POSIX_SPAWN_SETEXEC };
    struct _posix_spawn_args_desc desc = { .attrp = &attr };
    char* args[] = { (char*)"missing", NULL };
    char* env[] = { NULL };
    int calls = clone_calls, before = fd_count(), unpublished = -123;
    assert(sys_posix_spawn(&unpublished, "/definitely-missing-spawn-pidfd", &desc, args, env) == -ENOENT);
    assert(clone_calls == calls && fd_count() == before && unpublished == -123);
    scenario = NORMAL;
    attr.psa_flags = POSIX_SPAWN_SETPGROUP;
    attr.psa_pgroup = (unsigned int)-1;
    assert(sys_posix_spawn(&unpublished, "/bin/sh", &desc, args, env) == -EINVAL);
    assert_closed();
    assert(fd_count() == before && unpublished == -123 && application_pid == 0);
    errno = 0;
    assert(waitpid(-1, &status, __WCLONE | WNOHANG) == -1 && errno == ECHILD);
    set_handler(SIG_DFL);
    pid_t setexec = sys_fork();
    assert(setexec >= 0);
    if (setexec == 0) {
        attr.psa_flags = POSIX_SPAWN_SETEXEC;
        char* command[] = { (char*)"/bin/sh", (char*)"-c", (char*)"exit 13", NULL };
        sys_posix_spawn(NULL, "/bin/sh", &desc, command, env);
        _exit(99);
    }
    assert(waitpid(setexec, &status, 0) == setexec);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 13);
    puts(reuse ? "PASS: production spawn, descriptor lifecycle, EINTR, and deterministic PID reuse"
               : "PASS: production spawn, descriptor lifecycle, EINTR, and application-first reap (reuse not exercised)");
    return 0;
}
