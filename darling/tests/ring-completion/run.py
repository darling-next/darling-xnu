#!/usr/bin/env python3
"""Run production guest ring completion paths with a controlled host peer.

By default the paired server is the sibling darlingserver source directory.
DSERVER_SOURCE and DSERVER_GEN_INC may select explicit paired source/headers.
Otherwise rpc.h is generated in temporary state from the paired server.
RING_COMPLETION_PROFILE_ROOT locates the paired profile when West relocates this
fixture into an isolated source-base proof tree.
Requires Python 3 and a Linux C compiler with UBSan.
No server process or guest prefix is used. RING_COMPLETION_SOURCE_ROOT may select
an older XNU source tree for a regression RED run with this same fixture.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
source = Path(os.environ.get("RING_COMPLETION_SOURCE_ROOT", here.parents[2]))
profile = Path(os.environ.get("RING_COMPLETION_PROFILE_ROOT", here.parents[2]))
emulation = source / "darling/src/libsystem_kernel/emulation"
server = Path(os.environ.get("DSERVER_SOURCE", profile.parent / "darlingserver"))
generated_override = os.environ.get("DSERVER_GEN_INC")
if not (server / "include/darlingserver/rpc-supplement.h").is_file():
    raise SystemExit("DSERVER_SOURCE must contain the paired server source")

with tempfile.TemporaryDirectory(prefix="ring-completion-") as temporary:
    root = Path(temporary)
    generated = Path(generated_override) if generated_override else root / "generated/include"
    if generated_override is None:
        internal = root / "generated/internal-include/darlingserver/rpc.internal.h"
        wrapper = root / "generated/src/rpc.c"
        for directory in (generated / "darlingserver", internal.parent, wrapper.parent):
            directory.mkdir(parents=True, exist_ok=True)
        subprocess.run([sys.executable, "-B", str(server / "scripts/generate-rpc-wrappers.py"),
                        str(generated / "darlingserver/rpc.h"), str(internal), str(wrapper),
                        '"../include/darlingserver/rpc.h"'], check=True)
    if not (generated / "darlingserver/rpc.h").is_file():
        raise SystemExit("DSERVER_GEN_INC must contain the paired generated darlingserver/rpc.h")
    includes = root / "include"
    # As in spawn-pidfd, replace only platform-service headers. The complete
    # production dserver-ring.c is included unchanged, with the real server ABI.
    for name in ("common/base.h", "common/simple.h", "linux_premigration/linux-syscalls/linux.h"):
        target = includes / "darling/emulation" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("")
    for name in ("conversion/duct_errno.h", "linux_premigration/resources/dserver-ring.h",
                 "xnu_syscall/mach/impl/cached_self_ports.h"):
        target = includes / "darling/emulation" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((emulation / "include" / name).read_text())
    mach = includes / "mach/kern_return.h"
    mach.parent.mkdir(parents=True, exist_ok=True)
    mach.write_text("#define KERN_SUCCESS 0\n#define KERN_FAILURE 5\n")

    # Compile verbatim production callers, omitting unrelated Mach traps and their
    # Darwin SDK dependencies. Selection is not an oracle: all assertions exercise
    # the compiled functions, request publication, output state and UDS call count.
    traps = (emulation / "src/xnu_syscall/mach/impl/mach_traps.c").read_text()
    names = ("__darling_reset_cached_self_ports", "mach_reply_port_impl",
             "thread_self_trap_impl", "host_self_trap_impl", "__task_self_trap_rpc")
    callers = []
    for name in names:
        pattern = rf"^[^\n]*\b{re.escape(name)}\([^;{{}}]*\)\s*\{{\n.*?^\}}"
        matches = re.findall(pattern, traps, re.M | re.S)
        if len(matches) != 1:
            raise SystemExit(f"Cannot uniquely select production function {name}")
        callers.append(matches[0])
    (root / "mach-callers.inc").write_text("\n\n".join(callers) + "\n")
    binary = root / "ring-completion"
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                    "-fsanitize=undefined", "-fno-sanitize-recover=all",
                    "-I", str(includes), "-I", str(generated), "-I", str(server / "include"),
                    "-I", str(root), "-I", str(emulation / "src/linux_premigration/resources"),
                    str(here / "fixture.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=30)
