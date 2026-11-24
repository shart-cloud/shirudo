#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6107 -- the bpf() commands lsm/bpf leaves to shirudo's own executable
# or denies outright. A root process that is not shirudo gets EACCES for
# link creation, raw tracepoint opens and pins (a vetted program must
# not be re-attached where its signer never meant it to run, and the
# private bpffs takes no entries shirudo did not make), for opening a
# pin or a map or link by id (a held link stays attached after shirudo
# unpins it), for the tear-down and mutation commands the policy
# default-denies, and for an unclassified command; a read-only command
# is answered by the kernel.
# The hook decides before the kernel reads the attr, so every attr here
# is empty. Non-destructive: nothing is created.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
strict_guard

H=helper/test-bpf-cmd
[ -x "$H" ] || test_skip_all "test-bpf-cmd helper not built"

denied() {
	for c in "$@"; do
		[ "$(./$H "$c")" = "errno=13" ] || {
			echo "$c was not denied: $(./$H "$c")"
			return 1
		}
	done
}

test_expect_success 'link creation, raw tracepoint open and pin are shirudo-only' '
	denied LINK_CREATE RAW_TRACEPOINT_OPEN OBJ_PIN
'

test_expect_success 'opening a pin or a map or link by id is shirudo-only' '
	denied OBJ_GET MAP_GET_FD_BY_ID LINK_GET_FD_BY_ID
'

test_expect_success 'map creation, update, freeze and test run are shirudo-only' '
	denied MAP_CREATE MAP_UPDATE_ELEM MAP_FREEZE PROG_TEST_RUN
'

test_expect_success 'detach, update and delete commands are denied' '
	denied LINK_DETACH LINK_UPDATE PROG_ATTACH PROG_DETACH \
	       MAP_DELETE_ELEM MAP_LOOKUP_AND_DELETE_ELEM \
	       MAP_UPDATE_BATCH MAP_DELETE_BATCH BTF_LOAD
'

test_expect_success 'commands the policy never classified are denied' '
	denied ITER_CREATE PROG_BIND_MAP
'

test_expect_success 'a read-only command still reaches the kernel' '
	out=$(./$H MAP_GET_NEXT_ID) &&
	[ "$out" != "errno=13" ]
'

test_done
