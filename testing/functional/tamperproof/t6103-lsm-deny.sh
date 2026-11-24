#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6103 -- the core enforcement property: with shirudo's lsm/bpf hook
# attached, an unsigned userspace BPF_PROG_LOAD (kernel == false) is
# denied. The helper issues a raw bpf() load of a trivial program and
# reports the errno; the LSM rejects it with EACCES. Non-mutating: the
# load never succeeds, so nothing enters the kernel.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
strict_guard

H=helper/test-bpf-load
[ -x "$H" ] || test_skip_all "test-bpf-load helper not built"

test_expect_success 'unsigned userspace BPF_PROG_LOAD is denied (EACCES)' '
	out=$(./$H) &&
	echo "$out" | grep -qx "errno=13"
'

test_done
