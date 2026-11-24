#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6158 -- bpf.enforcement = own: a root process that is not shirudo
# loads, runs, pins and opens BPF objects of its own, as a network agent
# or a container runtime does, and still reaches none of shirudo's. A
# descriptor of shirudo's maps, programs and links, a pin in its private
# bpffs, a pin of root's there, an LSM program and a loader stay refused.
# Runs only on a target booted with that setting
# (TEST_VM_BPF_ENFORCEMENT=own).

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"
[ "$(bpf_enforcement)" = own ] ||
	test_skip_all "target does not run bpf.enforcement = own"

H=./helper/test-bpf-own
[ -x "$H" ] || test_skip_all "test-bpf-own helper not built"
W=$(mktemp -d)
trap 'umount "$W/bpffs" 2>/dev/null; rm -rf "$W"' EXIT
mkdir "$W/bpffs" && mount -t bpf bpf "$W/bpffs" ||
	test_skip_all "cannot mount a bpffs of the test's own"

# The count after "refused=" in the scan line $1.
refused() {
	printf '%s\n' "$1" | sed -n 's/.*refused=\([0-9]*\).*/\1/p'
}

test_expect_success 'status reports the mode init froze' '
	[ "$(bpf_enforcement)" = own ]
'

test_expect_success 'an unsigned program loads, runs and opens by id' '
	[ "$($H program)" = ok ]
'

test_expect_success 'a map of the caller is created, written, pinned and opened' '
	[ "$($H map "$W/bpffs/own_test")" = ok ]
'

test_expect_success 'the descriptors of the programs of shirudo are refused' '
	out=$($H scan prog) &&
	[ "$(refused "$out")" -gt 0 ]
'

test_expect_success 'the descriptors of the maps of shirudo are refused' '
	out=$($H scan map) &&
	[ "$(refused "$out")" -gt 0 ]
'

test_expect_success 'no link opens by id' '
	out=$($H scan link) &&
	case $out in "opened=0 "*) ;; *) false ;; esac
'

test_expect_success 'a pin in the private bpffs does not open' '
	[ "$($H get /run/shirudo/bpffs/lsm_link)" = errno=13 ]
'

test_expect_success 'the private bpffs takes no pin of another caller' '
	[ "$($H pin /run/shirudo/bpffs/own_pin)" = errno=1 ] &&
	[ ! -e /run/shirudo/bpffs/own_pin ]
'

test_expect_success 'an LSM program is refused' '
	[ "$($H lsm)" = errno=13 ]
'

test_expect_success 'a loader is refused' '
	[ "$($H loader)" = errno=13 ]
'

test_expect_success 'the guards stay attached after the other BPF use' '
	[ -e /run/shirudo/bpffs/lsm_link ] &&
	[ "$(bpf_enforcement)" = own ]
'

test_done
