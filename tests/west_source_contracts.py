#!/usr/bin/env python3
"""Source-level contracts used by workspace patch metadata.

The script intentionally checks small, load-bearing source invariants.  West
can run the same test asset against the current materialized profile (GREEN)
and against a patch's source-base worktree via XNU_SRC_ROOT (RED).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(os.environ.get("XNU_SRC_ROOT", Path.cwd())).resolve()


def read(rel: str) -> str:
    path = ROOT / rel
    try:
        return path.read_text()
    except FileNotFoundError:
        fail(f"missing source file: {rel}")


def fail(message: str) -> None:
    print(f"west_source_contracts: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(rel: str, *needles: str) -> None:
    data = read(rel)
    missing = [needle for needle in needles if needle not in data]
    if missing:
        fail(f"{rel} missing: {', '.join(missing)}")


def require_not(rel: str, *needles: str) -> None:
    data = read(rel)
    present = [needle for needle in needles if needle in data]
    if present:
        fail(f"{rel} still contains forbidden text: {', '.join(present)}")


VCHROOT_H = "darling/src/libsystem_kernel/emulation/include/linux_premigration/vchroot_expand.h"
VCHROOT_C = "darling/src/libsystem_kernel/emulation/src/linux_premigration/vchroot_userspace.c"
SELECT_FDSET_H = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/select/fdset.h"
SELECT_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/select/select.c"
PSELECT_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/select/pselect.c"
GETPRIORITY_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/process/getpriority.c"
SETPRIORITY_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/process/setpriority.c"
SOCKET_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/helper/ioctl/socket.c"
FORK_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/process/fork.c"
ELFCALLS_WRAPPER_C = "darling/src/libsystem_kernel/emulation/src/linux_premigration/elfcalls_wrapper.c"
ABORT_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/misc/abort_with_payload.c"
FD_FCNTL_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/fcntl/fcntl.c"
FD_DUP_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/unistd/dup.c"
FD_DUP2_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/unistd/dup2.c"
SIGACTION_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/signal/sigaction.c"
SIGEXC_C = "darling/src/libsystem_kernel/emulation/src/linux_premigration/signal/sigexc.c"
ULOCK_C = "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/psynch/ulock_wait.c"


def eunion_1() -> None:
    require(VCHROOT_C, "#ifdef EUNION", "libexec_path_len > 0", "prefix_path_len >= 0")


def eunion_2() -> None:
    require(VCHROOT_H, "int vchroot_copyup(const char* guest);")
    require(VCHROOT_C, "int vchroot_copyup(const char* guest)", ".union-work/cu.")


def eunion_3() -> None:
    require(VCHROOT_H, "int vchroot_whiteout(const char* guest);", "int vchroot_set_opaque(const char* guest);")
    require(VCHROOT_C, "EUNION_WH_XATTR", "EUNION_OPAQUE_XATTR", "int vchroot_whiteout(const char* guest)")


def eunion_4() -> None:
    require(VCHROOT_H, "int vchroot_readdir_merge(const char* guest, char* out, int cap);")
    require(VCHROOT_C, "int vchroot_readdir_merge(const char* guest, char* out, int cap)", "eunion_emit_name")


def eunion_5() -> None:
    require(VCHROOT_H, "int vchroot_prepare_write(const char* guest);", "int vchroot_post_unlink(const char* guest);")
    require(VCHROOT_C, "int vchroot_prepare_write(const char* guest)", "int vchroot_post_unlink(const char* guest)")


def eunion_6() -> None:
    require(
        VCHROOT_H,
        "int vchroot_getdents_merge(int fd, char* out, int cap);",
        "kernel open-file-description offset",
    )
    require(
        VCHROOT_C,
        "int vchroot_getdents_merge(int fd, char* out, int cap)",
        "__NR_lseek, fd, 0, LINUX_SEEK_CUR",
        "EUNION_SIDECAR_ACCESS_EXCLUSIVE",
    )
    require_not(
        VCHROOT_C,
        "EUNION_MAXDIRS",
        "eunion_dir_descriptions",
        "eunion_dirs_lock_word",
        "void vchroot_dir_closed(int fd)",
        "void vchroot_dir_rewind(int fd)",
        "int vchroot_dir_dup(int oldfd, int newfd)",
    )
    for wrapper in (
        FD_DUP_C,
        FD_DUP2_C,
        FD_FCNTL_C,
        "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/unistd/close.c",
        "darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/unistd/lseek.c",
    ):
        require_not(wrapper, "vchroot_dir_dup", "vchroot_dir_closed", "vchroot_dir_rewind")


def eunion_7() -> None:
    require(VCHROOT_C, "static void eunion_init_from_prefix(void)", "/.union-work")


def eunion_8() -> None:
    require("darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/network/bind.c", "AF_UNIX", "vchroot_prepare_write(parent)")


def eunion_9() -> None:
    require(VCHROOT_C, "Union inactive", "return LINUX_SYSCALL(__NR_getdents64, fd, out, cap);")


def eunion_10() -> None:
    require(VCHROOT_C, "vchroot_unexpand", "detranslates upper AND lower -> guest", "EXIT_PATH")


def eunion_11() -> None:
    require(VCHROOT_H, "int vchroot_copyup_tree(const char* guest);", "int vchroot_prepare_write_at(int dfd, const char* rel);")
    require(VCHROOT_C, "int vchroot_copyup_tree(const char* guest)", "int vchroot_prepare_write_at(int dfd, const char* rel)", "eunion_copy_xattrs")


def eunion_12() -> None:
    require(VCHROOT_H, "VCHROOT_UNLINK_SKIP", "int vchroot_prepare_rename_dest(const char* guest);", "int vchroot_prepare_create(const char* guest);")
    require(VCHROOT_C, "int vchroot_prepare_unlink(const char* guest)", "int vchroot_prepare_rename_dest(const char* guest)", "int vchroot_prepare_create(const char* guest)")


def eunion_13() -> None:
    require(VCHROOT_C, "LINUX_SYSCALL(__NR_fchmod, dfd, mode & 0777)", "security.capability")


def eunion_14() -> None:
    require(VCHROOT_H, "int vchroot_fd_for_meta_write(int fd);")
    require(VCHROOT_C, "int vchroot_fd_for_meta_write(int fd)", "vchroot_prepare_write_fd(fd, guest, sizeof(guest))")


def eunion_15() -> None:
    require(VCHROOT_H, "int vchroot_xattr_is_marker(const char* name);")
    require(VCHROOT_C, "static const char EUNION_MARKER_NS[] = \"user.union.\";", "int vchroot_xattr_is_marker(const char* name)")


def eunion_16() -> None:
    require(VCHROOT_H, "int vchroot_post_mkdir(const char* guest);")
    require(VCHROOT_C, "int vchroot_post_mkdir(const char* guest)", "return vchroot_set_opaque(guest);")


def eunion_17() -> None:
    require(VCHROOT_C, "static void eunion_stat_mtime", "static unsigned char eunion_dt_from_mode", "eunion_emit_dirent")


def eunion_18() -> None:
    require(VCHROOT_C, "static int eunion_ascii_ncasecmp", "eunion_ascii_ncasecmp(ctxt->current_path")
    require_not(VCHROOT_C, "strncasecmp_l(ctxt->current_path")


def eunion_20() -> None:
    require(VCHROOT_H, "int vchroot_fd_for_content_write(int fd);")
    require(VCHROOT_C, "int vchroot_fd_for_content_write(int fd)", "LINUX_O_RDWR | LINUX_O_NOFOLLOW")


def eunion_22() -> None:
    require(VCHROOT_C, "static int eunion_copyup_dir_resolved(const char* dir)", "EUNION_MAX_DIR_SYMLINK_HOPS", "return eunion_copyup_dir_resolved(parent);")


def select_pselect_fdset() -> None:
    require(SELECT_FDSET_H, "BSD_FDSET_BITS_PER_WORD", "bsd_fdset_to_linux", "linux_fdset_to_bsd")
    require(SELECT_C, "bsd_fdset_to_linux", "linux_fdset_to_bsd")
    require(PSELECT_C, "bsd_fdset_to_linux", "linux_fdset_to_bsd")


def darwin_priority() -> None:
    require(GETPRIORITY_C, "which == PRIO_DARWIN_THREAD", "which == PRIO_DARWIN_PROCESS")
    require(SETPRIORITY_C, "prio == PRIO_DARWIN_BG", "prio == PRIO_DARWIN_NONUI")


def socket_siocgifconf() -> None:
    require(SOCKET_C, "case 0xC00C6924:", "ifc->ifc_len = 0;", "return IOCTL_HANDLED;")


def fork_postfork_child() -> None:
    require(ELFCALLS_WRAPPER_C, "void __mldr_postfork_child(void)", "elfcalls()->postfork_child()")
    require(FORK_C, "__mldr_postfork_child();")


def abort_with_payload_no_group_broadcast() -> None:
    require(ABORT_C, "__NR_tgkill", "__NR_gettid", "signum_bsd_to_linux(SIGABRT)")
    require_not(ABORT_C, "sys_kill(0")


def fd_guard_ebadf() -> None:
    require(FD_FCNTL_C, "guard_table_check(fd, guard_flag_prevent_close)", "return -EBADF;")
    require(FD_DUP_C, "guard_table_check(fd, guard_flag_prevent_close)", "return -EBADF;")
    require(FD_DUP2_C, "guard_table_check(fd_to, guard_flag_prevent_close)", "guard_table_check(fd_from, guard_flag_prevent_close)")


def sigexc_sa_restart() -> None:
    require(SIGACTION_C, "sigexc_set_restart(linux_signum, restart)", "nsa->sa_flags & BSD_SA_RESTART")
    require(SIGEXC_C, "long sigexc_set_restart(int linux_signum, bool restart)", "sa.sa_flags |= LINUX_SA_RESTART")


def sigexc_debug_flood() -> None:
    require(SIGEXC_C, "#ifdef DEBUG_SIGEXC")
    require_not(SIGEXC_C, "#define DEBUG_SIGEXC")


def sigexc_default_resend_self() -> None:
    require(SIGEXC_C, "__NR_tgkill", "__NR_gettid", "linux_signum")
    require_not(SIGEXC_C, "sys_kill(0, linux_signum)")


def ulock_wait_eintr_retry() -> None:
    require(ULOCK_C, "retry on EINTR instead of returning it", "while (ret == -LINUX_EINTR && timeout == 0)")


CASES = {
    name.replace("_", "-"): value
    for name, value in sorted(globals().items())
    if callable(value) and not name.startswith("_") and name not in {"read", "fail", "require", "require_not"}
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in CASES:
        print("usage: west_source_contracts.py CASE", file=sys.stderr)
        print("cases:", ", ".join(CASES), file=sys.stderr)
        return 2
    CASES[argv[1]]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
