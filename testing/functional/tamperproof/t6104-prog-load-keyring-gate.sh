#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6104 -- the lsm/bpf_prog_load admission gate binds the load to the
# sealed "shirudo" keyring's serial. A signed loader whose signature is
# perfectly valid -- but verified against a keyring the caller controls
# rather than the shirudo keyring -- is denied in-kernel with EACCES by
# the admission hook, AFTER the kernel recorded BPF_SIG_VERIFIED. This is
# the bypass the load-time scheme closes: before the hook existed, any
# CAP_BPF caller could sign a SYSCALL loader against their own keyring and
# load it. Distinct from t6102 (cert absent -> ENOKEY): here the signature
# passes and the hook is what refuses.
#
# Non-destructive: mints a throwaway key/cert, adds the cert only to this
# process's own session keyring, and never touches shirudo's keyring or
# any pinned state.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
strict_guard

H=helper/test-signed-load
[ -x "$H" ] || test_skip_all "test-signed-load helper not built"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
OWN="$FIXTURES/shirudo-test-own-keyring.upatch"
OWN_CERT="$FIXTURES/own.der"
[ -s "$OWN" ] || test_skip_all "missing own-keyring fixture"
[ -s "$OWN_CERT" ] || test_skip_all "missing own-keyring certificate"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# EACCES (13) is the admission-hook denial. A signature failure would be
# ENOKEY (126) or EKEYREJECTED (129) instead; assert it is neither, so a
# regression that stopped enforcing the keyring bind cannot pass by
# accidentally failing the signature.
test_expect_success 'valid signature, non-shirudo keyring -> denied (EACCES by the hook, EPERM by the kernel)' '
	out=$(./$H "$OWN" "$OWN_CERT") &&
	echo "own-keyring load: $out (keyring mode $(keyring_mode))" &&
	[ "$out" = "errno=$(foreign_keyring_errno)" ]
'

test_done
