#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${XNU_SRC_ROOT:-$(git -C "$here" rev-parse --show-toplevel)}"
src="$here/psynch_return_contract_test.c"
include="$root/darling/src/libsystem_kernel/emulation/include"
impl="$root/darling/src/libsystem_kernel/emulation/src/xnu_syscall/bsd/impl/psynch"
stub_include="$(mktemp -d /tmp/psynch-return-contract-include.XXXXXX)"
out="$(mktemp /tmp/psynch-return-contract.XXXXXX)"
trap 'rm -rf "$stub_include" "$out"' EXIT

mkdir -p \
	"$stub_include/darling/emulation/xnu_syscall/bsd/impl/psynch" \
	"$stub_include/darling/emulation/common" \
	"$stub_include/darling/emulation/conversion" \
	"$stub_include/darling/emulation/linux_premigration/linux-syscalls" \
	"$stub_include/darlingserver"

cat > "$stub_include/darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_cvwait.h" <<'EOF'
#include <stdint.h>
long sys_psynch_cvwait(void*, uint64_t, uint32_t, void*, uint64_t, uint32_t, int64_t, uint32_t);
EOF
cat > "$stub_include/darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_mutexwait.h" <<'EOF'
#include <stdint.h>
long sys_psynch_mutexwait(void*, uint32_t, uint32_t, uint64_t, uint32_t);
EOF
cat > "$stub_include/darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_rw_rdlock.h" <<'EOF'
#include <stdint.h>
long sys_psynch_rw_rdlock(void*, uint32_t, uint32_t, uint32_t, int);
EOF
cat > "$stub_include/darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_rw_wrlock.h" <<'EOF'
#include <stdint.h>
long sys_psynch_rw_wrlock(void*, uint32_t, uint32_t, uint32_t, int);
EOF
cat > "$stub_include/darling/emulation/xnu_syscall/bsd/impl/psynch/psynch_return.h" <<'EOF'
#include <xnu_syscall/bsd/impl/psynch/psynch_return.h>
EOF
cat > "$stub_include/darling/emulation/common/base.h" <<'EOF'
#include <errno.h>
EOF
cat > "$stub_include/darling/emulation/linux_premigration/linux-syscalls/linux.h" <<'EOF'
#define LINUX_EINTR 4
EOF
cat > "$stub_include/darling/emulation/common/simple.h" <<'EOF'
#include <stdarg.h>
#include <stdlib.h>
static inline void __simple_printf(const char* format, ...) { (void)format; }
static inline void __simple_abort(void) { abort(); }
EOF
cat > "$stub_include/darling/emulation/conversion/duct_errno.h" <<'EOF'
EOF
cat > "$stub_include/darlingserver/rpc.h" <<'EOF'
#include <stdint.h>
int dserver_rpc_psynch_cvwait(void*, uint64_t, uint32_t, void*, uint64_t, uint32_t, int64_t, uint32_t, uint32_t*);
int dserver_rpc_psynch_mutexwait(void*, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t*);
int dserver_rpc_psynch_rw_rdlock(void*, uint32_t, uint32_t, uint32_t, int, uint32_t*);
int dserver_rpc_psynch_rw_wrlock(void*, uint32_t, uint32_t, uint32_t, int, uint32_t*);
EOF

cc -std=c11 -Wall -Wextra \
	-I "$stub_include" \
	-I "$include" \
	"$src" \
	"$impl/psynch_cvwait.c" \
	"$impl/psynch_mutexwait.c" \
	"$impl/psynch_rw_rdlock.c" \
	"$impl/psynch_rw_wrlock.c" \
	-o "$out"
"$out" | grep -q '^PSYNCH_RETURN_CONTRACT_OK$'
