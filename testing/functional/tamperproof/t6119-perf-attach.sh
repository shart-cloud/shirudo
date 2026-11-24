#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6119 -- PERF_EVENT_IOC_SET_BPF is the one attach that never passes
# through bpf(): a kprobe-type program a signed loader created is
# root's to reach by id, and the ioctl would bind it to a perf event of
# root's own, a probe where its signer never meant it to run. The
# file_ioctl hook keeps the ioctl to shirudo, counted as PerfAttach; the
# upatch's own link is untouched. Needs the uprobe PMU.
# A kprobe multi link of root's own for such a program goes through
# bpf(), where the same kind of attach is refused and counted as
# ProgAttach; that case needs CONFIG_FPROBE, which the test kernel has.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
strict_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

H=helper/test-perf-attach
[ -x "$H" ] || test_skip_all "test-perf-attach helper not built"
[ -r /sys/bus/event_source/devices/uprobe/type ] ||
	test_skip_all "no uprobe PMU"
FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=shirudo-test-uprobe-multi
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
TARGET="$FIXTURES/shirudo-test-uprobe-target"
RUNTIME=/tmp/shirudo-test-uprobe-target
PIN="/run/shirudo/bpffs/upatches/$NAME/link"
KM_NAME=shirudo-test-kprobe-multi
KM_LOAD="$FIXTURES/$KM_NAME.upatch"
KM_UNLOAD="$FIXTURES/$KM_NAME.unload.upatch"
KM_DIR="/run/shirudo/bpffs/upatches/$KM_NAME"
for f in "$LOAD" "$UNLOAD" "$TARGET" "$KM_LOAD" "$KM_UNLOAD"; do
	[ -s "$f" ] || test_skip_all "missing fixture $f"
done
cleanup() {
	if [ -e "$PIN" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck >/dev/null 2>&1 || true
	fi
	if [ -e "$KM_DIR/link_0" ]; then
		"$SHIRUDO_BIN" upatch unload "$KM_UNLOAD" --no-precheck >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

# The counter $1 from status --json.
counter() {
	"$SHIRUDO_BIN" status --json | python3 -c '
import json, sys
print(json.load(sys.stdin)["tamper_attempts"]["counters"][sys.argv[1]])
' "$1"
}

cp "$TARGET" "$RUNTIME"
"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 ||
	test_skip_all "kernel does not support this uprobe.multi load"

test_expect_success 'root cannot bind the loaded program to a perf event of its own' '
	before=$(counter PerfAttach) &&
	[ "$(./$H probe)" = "errno=13" ] &&
	[ "$(counter PerfAttach)" -gt "$before" ] &&
	[ -e "$PIN" ]
'

test_expect_success 'the kprobe multi upatch loads' '
	"$SHIRUDO_BIN" upatch load "$KM_LOAD" --no-precheck >/dev/null &&
	[ -e "$KM_DIR/link_0" ]
'

test_expect_success 'root cannot create a kprobe multi link for a loaded program' '
	before=$(counter ProgAttach) &&
	[ "$(./$H --kprobe-multi km_entry)" = "errno=13" ] &&
	[ "$(counter ProgAttach)" -gt "$before" ] &&
	[ -e "$KM_DIR/link_0" ]
'

test_expect_success 'the kprobe multi upatch unloads' '
	"$SHIRUDO_BIN" upatch unload "$KM_UNLOAD" --no-precheck >/dev/null &&
	[ ! -e "$KM_DIR/link_0" ]
'

test_done
