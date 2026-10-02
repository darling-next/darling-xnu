#!/usr/bin/env python3
"""Compile the production spawn/fork sources with host runtime adapters and run.

Native: python3 darling/tests/spawn-pidfd/run.py
Deterministic reuse (isolated namespace, never alter host ns_last_pid):
  python3 darling/tests/spawn-pidfd/run.py --reuse
Requires a Linux >= 5.4 host and a C compiler. --reuse also requires permission
for ns_last_pid in that private namespace; a denied prerequisite fails explicitly.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

here = Path(__file__).resolve().parent
arguments = sys.argv[1:]
if arguments == ["--reuse"]:
    original_namespace = os.readlink("/proc/self/ns/pid")
    namespace = ["unshare"]
    if os.geteuid() != 0:
        namespace += ["--user", "--map-root-user"]
    subprocess.run([*namespace, "--pid", "--fork", "--mount-proc",
                    sys.executable, str(Path(__file__).resolve()),
                    "--in-reuse-namespace", original_namespace], check=True)
    sys.exit(0)
if len(arguments) == 2 and arguments[0] == "--in-reuse-namespace":
    if os.readlink("/proc/self/ns/pid") == arguments[1] or os.getpid() != 1:
        raise SystemExit("Refusing ns_last_pid write outside a fresh private PID namespace")
    arguments = ["--reuse"]
elif arguments:
    raise SystemExit("usage: run.py [--reuse]")
source_root = Path(os.environ.get("SPAWN_PIDFD_SOURCE_ROOT", here.parents[2]))
emulation = source_root / "darling/src/libsystem_kernel/emulation"
production = emulation / "src/xnu_syscall/bsd/impl/process"
with tempfile.TemporaryDirectory(prefix="spawn-pidfd-") as temporary:
    root = Path(temporary)
    includes = root / "include"
    # Only replace platform/runtime headers; the implementation itself is compiled
    # unchanged. Real Darwin spawn structures and syscall macros remain in use.
    for source in (production / "fork.c", production / "posix_spawn.c"):
        for name in re.findall(r"^#include <([^>]+)>", source.read_text(), re.M):
            if name.startswith(("darling/", "darlingserver/")) or name in ("_libkernel_init.h", "sys/spawn.h"):
                target = includes / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("")
    for name in ("common/base.h", "xnu_syscall/bsd/impl/process/fork.h",
                 "xnu_syscall/bsd/impl/process/posix_spawn.h", "conversion/process/posix_spawn.h",
                 "linux_premigration/resources/dserver-ring.h"):
        target = includes / "darling/emulation" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((emulation / "include" / name).read_text())
    mach = includes / "mach/mach_port.h"
    mach.parent.mkdir(parents=True, exist_ok=True)
    mach.write_text("typedef unsigned int mach_port_name_t;\n")
    binary = root / "spawn-pidfd"
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O0", "-g", "-Wall", "-Wextra",
                    "-Wno-unused-parameter", "-I", str(includes), "-I", str(production),
                    str(here / "fixture.c"), "-o", str(binary)], check=True)
    subprocess.run([str(binary), *arguments], check=True, timeout=30)
