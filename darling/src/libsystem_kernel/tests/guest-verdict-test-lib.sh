#!/usr/bin/env bash

guest_verdict_run_c() {
	local name="$1" src="$2" ok_marker="$3"
	local timeout_seconds="${4:-60}"
	local run_id="${BASHPID:-$$}.$RANDOM"
	local output="/tmp/$name.$run_id"
	local guest_src="/tmp/$name.$run_id.c"
	local verdict="/tmp/$name.$run_id.verdict"
	local runner_log="/tmp/$name.$run_id.runner.log"
	local launch="${DARLING_LAUNCHER:-${DARLING:-darling}}"
	local guest_cc="${DARLING_GUEST_CC:-/Library/Developer/CommandLineTools/usr/bin/clang}"
	local guest_cflags="${DARLING_GUEST_CFLAGS:--isysroot /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk}"
	local poll_timeout="${GUEST_VERDICT_POLL_TIMEOUT:-10}"

	: "${DPREFIX:?set DPREFIX to a bootable Darling prefix}"

	guest_verdict_shell() {
		local seconds="$1"
		shift
		timeout --kill-after=5 "$seconds" env DPREFIX="$DPREFIX" "$launch" shell /bin/bash --login -c "$*"
	}

	rm -f "$DPREFIX$verdict" 2>/dev/null || true
	guest_verdict_shell "$poll_timeout" "rm -f '$verdict' '$guest_src' '$output'" >/dev/null 2>&1 || true
	timeout --kill-after=5 "$poll_timeout" env DPREFIX="$DPREFIX" "$launch" \
		shell /bin/bash --login -c "cat > '$guest_src'" < "$src"

	local guest_cc_literal=""
	printf -v guest_cc_literal "%q" "$guest_cc"
	guest_verdict_shell "$timeout_seconds" "
		guest_cc=$guest_cc_literal
		if [ ! -x \"\$guest_cc\" ]; then guest_cc=clang; fi
		\"\$guest_cc\" $guest_cflags -O2 -Wall -Wextra -o '$output' '$guest_src' > '$verdict' 2>&1
		rc=\$?
		if [ \"\$rc\" -ne 0 ]; then
			printf 'ORACLE_RC=%s\n' \"\$rc\" >> '$verdict'
			exit 0
		fi
		'$output' > '$verdict' 2>&1
		rc=\$?
		printf 'ORACLE_RC=%s\n' \"\$rc\" >> '$verdict'
	" </dev/null > "$runner_log" 2>&1 &
	local shell_pid=$!

	local deadline=$((SECONDS + timeout_seconds))
	while [ "$SECONDS" -lt "$deadline" ]; do
		if guest_verdict_shell "$poll_timeout" \
			"test -f '$verdict' && grep -q '^ORACLE_RC=' '$verdict'" >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done

	if ! guest_verdict_shell "$poll_timeout" \
		"test -f '$verdict' && grep -q '^ORACLE_RC=' '$verdict'" >/dev/null 2>&1; then
		kill "$shell_pid" 2>/dev/null || true
		wait "$shell_pid" 2>/dev/null || true
		echo "=== runner log ==="
		grep -vE "Xlib|libGL|MESA|X11" "$runner_log" 2>/dev/null || true
		echo "no verdict produced before timeout"
		return 2
	fi

	kill "$shell_pid" 2>/dev/null || true
	wait "$shell_pid" 2>/dev/null || true

	echo "=== verdict ==="
	local guest_verdict
	guest_verdict="$(guest_verdict_shell "$poll_timeout" "cat '$verdict'" 2>/dev/null || true)"
	printf '%s\n' "$guest_verdict"
	grep -q "^$ok_marker" <<<"$guest_verdict" &&
		grep -q "ORACLE_RC=0" <<<"$guest_verdict"
}
