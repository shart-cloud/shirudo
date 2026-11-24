#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6145 -- a shirudo task that dumps core acts without authority: an exec
# of the runtime binary that fails after its mark is committed dumps core
# as the marked task, and the dump's unlink of the path core_pattern names
# is refused for a pin and a sealed file alike, and counted.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
H=helper/test-exec-fail
[ -x "$H" ] || test_skip_all "test-exec-fail helper not built"
RUNTIME=$(runtime_binary)
[ -x "$RUNTIME" ] || test_skip_all "no runtime binary"
PIN=/run/shirudo/bpffs/lsm_link
SEALED=/var/lib/shirudo/eventlog
[ -s "$SEALED" ] || test_skip_all "no eventlog"
PATTERN=$(cat /proc/sys/kernel/core_pattern)
USES_PID=$(cat /proc/sys/kernel/core_uses_pid)
cleanup() {
	printf '%s\n' "$PATTERN" >/proc/sys/kernel/core_pattern || :
	printf '%s\n' "$USES_PID" >/proc/sys/kernel/core_uses_pid || :
}
trap cleanup EXIT
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}
dumps=$(counter SealCoreDump) || test_skip_all "no tamper counters"
echo 0 >/proc/sys/kernel/core_uses_pid

# The exec must fail after its commit, or nothing below tests the seal.
test_expect_success 'an exec of the runtime that runs out of stack dies by SIGSEGV' '
	echo core >/proc/sys/kernel/core_pattern &&
	[ "$("$H" "$RUNTIME")" = "signal 11" ]
'
test_expect_success 'the core dump cannot unlink a pin of the private bpffs' '
	before=$(counter PinUnlink) &&
	printf "%s\n" "$PIN" >/proc/sys/kernel/core_pattern &&
	[ "$("$H" "$RUNTIME")" = "signal 11" ] &&
	echo core >/proc/sys/kernel/core_pattern &&
	[ -e "$PIN" ] &&
	[ "$(counter PinUnlink)" -gt "$before" ]
'
test_expect_success 'the core dump cannot replace a sealed file' '
	before=$(counter SealUnlink) &&
	size=$(stat -c %s "$SEALED") &&
	inode=$(stat -c %i "$SEALED") &&
	printf "%s\n" "$SEALED" >/proc/sys/kernel/core_pattern &&
	[ "$("$H" "$RUNTIME")" = "signal 11" ] &&
	echo core >/proc/sys/kernel/core_pattern &&
	[ "$(stat -c %i "$SEALED")" = "$inode" ] &&
	[ "$(stat -c %s "$SEALED")" = "$size" ] &&
	[ "$(counter SealUnlink)" -gt "$before" ]
'
test_expect_success 'the dump that lost its authority is counted as SealCoreDump' '
	[ "$(counter SealCoreDump)" -ge $((dumps + 2)) ]
'
test_expect_success 'enforcement holds after the dumps' '
	bpf_gate_live &&
	"$SHIRUDO_BIN" status 2>/dev/null | grep -q "LsmAttached *OK"
'
test_done
