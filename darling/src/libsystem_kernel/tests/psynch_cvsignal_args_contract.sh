#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${XNU_SRC_ROOT:-$(git -C "$here" rev-parse --show-toplevel)}"
header="$root/darling/src/libsystem_kernel/emulation/include/xnu_syscall/bsd/impl/psynch/psynch_cvsignal.h"
cvsignal="$root/darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/psynch/psynch_cvsignal.c"
cvbroad="$root/darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/psynch/psynch_cvbroad.c"

fail() {
	printf 'psynch_cvsignal_args_contract: %s\n' "$*" >&2
	exit 1
}

[ -f "$header" ] || fail "header not found at $header"
[ -f "$cvsignal" ] || fail "cvsignal source not found at $cvsignal"
[ -f "$cvbroad" ] || fail "cvbroad source not found at $cvbroad"

python3 - "$header" "$cvsignal" "$cvbroad" <<'PY'
from pathlib import Path
import re
import sys

header = Path(sys.argv[1]).read_text()
cvsignal = Path(sys.argv[2]).read_text()
cvbroad = Path(sys.argv[3]).read_text()

def normalized_signature(text, name):
    match = re.search(rf"long\s+{name}\s*\((.*?)\)", text, re.S)
    if not match:
        raise SystemExit(f"{name} signature not found")
    return " ".join(match.group(1).split())

sig_header = normalized_signature(header, "sys_psynch_cvsignal")
sig_impl = normalized_signature(cvsignal, "sys_psynch_cvsignal")
required = (
    "void* cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, "
    "void* mutex, uint64_t mugen, uint64_t tid, uint32_t flags"
)
if sig_header != required:
    raise SystemExit(f"header signature mismatch: {sig_header}")
if sig_impl != required:
    raise SystemExit(f"implementation signature mismatch: {sig_impl}")

call = re.search(r"dserver_rpc_psynch_cvbroad\s*\((.*?)\)", cvbroad, re.S)
if not call:
    raise SystemExit("dserver_rpc_psynch_cvbroad call not found")
args = [part.strip() for part in call.group(1).replace("\n", " ").split(",")]
expected = ["cv", "cvlsgen", "cvudgen", "flags", "mutex", "mugen", "tid", "&retval"]
if args != expected:
    raise SystemExit(f"cvbroad RPC args mismatch: {args}")
PY

printf 'PSYNCH_CVSIGNAL_ARGS_CONTRACT_OK\n'
