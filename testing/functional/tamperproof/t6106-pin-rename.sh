#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6106 -- rename inside the private bpffs. The VFS asks only the rename
# hook of a rename and unlinks the victim without inode_unlink, so
# before bpf2's lsm/inode_rename a root `mv` of any pin over a link's
# pin dropped that link's only reference and detached the hook without
# a guard firing. Both the plain rename of a pin and the rename over
# the lsm/bpf link's pin must now be refused with EPERM, the pins must
# still be there and enforcement must survive. Non-destructive when the
# guard works; the trap re-inits if a regression unpinned the link.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

H=helper/test-bpf-load
[ -x "$H" ] || test_skip_all "test-bpf-load helper not built"
B=/run/shirudo/bpffs
[ -e "$B/identity" ] || test_skip_all "no identity pin at $B/identity"

restore() {
	[ -e "$B/lsm_link" ] || "$SHIRUDO_BIN" init >/dev/null 2>&1 || true
}
trap restore EXIT

# rename(2) of $1 to $2: prints the errno, 0 for success.
RENAME='
import errno, os, sys
try:
    os.rename(sys.argv[1], sys.argv[2])
    print(0)
except OSError as e:
    print(e.errno)
'

test_expect_success 'baseline: unsigned userspace load is denied' '
	bpf_gate_live
'

test_expect_success 'renaming a pin to another name is refused' '
	[ "$(python3 -c "$RENAME" "$B/identity" "$B/t6106-moved")" = 1 ] &&
	[ -e "$B/identity" ] && [ ! -e "$B/t6106-moved" ]
'

test_expect_success 'renaming a pin over the lsm/bpf link pin is refused' '
	[ "$(python3 -c "$RENAME" "$B/identity" "$B/lsm_link")" = 1 ] &&
	[ -e "$B/identity" ] && [ -e "$B/lsm_link" ] &&
	bpf_gate_live
'

test_expect_success 'renaming the lsm/bpf link pin itself is refused' '
	[ "$(python3 -c "$RENAME" "$B/lsm_link" "$B/t6106-link")" = 1 ] &&
	[ -e "$B/lsm_link" ] && [ ! -e "$B/t6106-link" ] &&
	bpf_gate_live
'

test_done
