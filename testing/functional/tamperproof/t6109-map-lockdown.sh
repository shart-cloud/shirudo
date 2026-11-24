#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6109 -- a root process with a different executable cannot take hold
# of shirudo's maps: no descriptor by pin or by id, read-only or
# writable, and no read of a pin as a file. A serializer program it
# reaches by id cannot be test-run to drain what the map export reads.
# PR_SET_MM executable spoofing is covered separately by t6110.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
strict_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
NAME=kernel-obs
LOAD="$FIXTURES/$NAME.upatch"
UNLOAD="$FIXTURES/$NAME.unload.upatch"
PIN="/run/shirudo/bpffs/upatches/$NAME/link_0"
MAPS="/run/shirudo/bpffs/upatches/$NAME/maps"
WORK=$(mktemp -d)

cleanup()
{
	if [ -e "$PIN" ] || [ -e "/run/shirudo/bpffs/upatches/$NAME/link" ]; then
		"$SHIRUDO_BIN" upatch unload "$UNLOAD" --no-precheck \
			>/dev/null 2>&1 || true
	fi
	rm -f "/var/lib/shirudo/upatches/$NAME.upatch"
	rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

[ -s "$LOAD" ] || test_skip_all "missing kernel-obs fixture"
[ -s "$UNLOAD" ] || test_skip_all "missing kernel-obs unload fixture"

cat >"$WORK/check.py" <<'PYTHON'
import ctypes
import errno
import json
import os
import platform
import subprocess
import sys

BPF_OBJ_GET = 7
BPF_PROG_TEST_RUN = 10
BPF_PROG_GET_NEXT_ID = 11
BPF_MAP_GET_NEXT_ID = 12
BPF_PROG_GET_FD_BY_ID = 13
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_F_RDONLY = 1 << 3
SYSCALLS = {"x86_64": 321, "aarch64": 280, "riscv64": 280}

try:
    BPF_SYSCALL = SYSCALLS[platform.machine()]
except KeyError as exc:
    machine = platform.machine()
    raise SystemExit(f"unsupported syscall architecture: {machine}") from exc

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long


class ObjGetAttr(ctypes.Structure):
    _fields_ = [("pathname", ctypes.c_uint64),
                ("bpf_fd", ctypes.c_uint32),
                ("file_flags", ctypes.c_uint32)]


class IdAttr(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint32),
                ("next_id", ctypes.c_uint32),
                ("open_flags", ctypes.c_uint32)]


class ObjInfoAttr(ctypes.Structure):
    _fields_ = [("bpf_fd", ctypes.c_uint32),
                ("info_len", ctypes.c_uint32),
                ("info", ctypes.c_uint64)]


class ProgInfoPrefix(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32),
                ("id", ctypes.c_uint32),
                ("tag", ctypes.c_uint8 * 8),
                ("jited_prog_len", ctypes.c_uint32),
                ("xlated_prog_len", ctypes.c_uint32),
                ("jited_prog_insns", ctypes.c_uint64),
                ("xlated_prog_insns", ctypes.c_uint64),
                ("load_time", ctypes.c_uint64),
                ("created_by_uid", ctypes.c_uint32),
                ("nr_map_ids", ctypes.c_uint32),
                ("map_ids", ctypes.c_uint64),
                ("name", ctypes.c_char * 16)]


class SerializerCtx(ctypes.Structure):
    _fields_ = [("magic", ctypes.c_uint32),
                ("version", ctypes.c_uint32),
                ("flags", ctypes.c_uint32),
                ("max_chunks", ctypes.c_uint32),
                ("chunk_payload_size", ctypes.c_uint32),
                ("page_index", ctypes.c_uint32),
                ("cursor", ctypes.c_uint64),
                ("invocation_id", ctypes.c_uint64)]


class ProgTestRunAttr(ctypes.Structure):
    _fields_ = [("prog_fd", ctypes.c_uint32),
                ("retval", ctypes.c_uint32),
                ("data_size_in", ctypes.c_uint32),
                ("data_size_out", ctypes.c_uint32),
                ("data_in", ctypes.c_uint64),
                ("data_out", ctypes.c_uint64),
                ("repeat", ctypes.c_uint32),
                ("duration", ctypes.c_uint32),
                ("ctx_size_in", ctypes.c_uint32),
                ("ctx_size_out", ctypes.c_uint32),
                ("ctx_in", ctypes.c_uint64),
                ("ctx_out", ctypes.c_uint64),
                ("flags", ctypes.c_uint32),
                ("cpu", ctypes.c_uint32),
                ("batch_size", ctypes.c_uint32)]


def bpf(cmd, attr):
    ctypes.set_errno(0)
    result = libc.syscall(BPF_SYSCALL, cmd, ctypes.byref(attr),
                          ctypes.sizeof(attr))
    return result, ctypes.get_errno()


def assert_denied(result, label):
    fd, error = result
    if fd >= 0:
        os.close(fd)
        raise AssertionError(f"{label}: unexpectedly allowed")
    if error != errno.EACCES:
        raise AssertionError(f"{label}: errno={error}, expected EACCES")


def obj_get(path, flags):
    name = ctypes.create_string_buffer(os.fsencode(path) + b"\0")
    return bpf(BPF_OBJ_GET, ObjGetAttr(ctypes.addressof(name), 0, flags))


def ids(cmd):
    current = 0
    while True:
        attr = IdAttr(current, 0, 0)
        result, _ = bpf(cmd, attr)
        if result < 0:
            return
        current = attr.next_id
        yield current


def open_file(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        return -1, exc.errno
    return fd, 0


pins = [os.path.join(sys.argv[1], name) for name in os.listdir(sys.argv[1])
        if not os.path.isdir(os.path.join(sys.argv[1], name))]
if not pins:
    raise AssertionError(f"no map pins under {sys.argv[1]}")
pins.append(os.path.join(os.path.dirname(sys.argv[1]), "serializers/exec"))
for pin in pins:
    assert_denied(obj_get(pin, 0), f"writable fd for {pin}")
    assert_denied(obj_get(pin, BPF_F_RDONLY), f"read-only fd for {pin}")
    assert_denied(open_file(pin), f"open of {pin}")

maps = 0
for map_id in ids(BPF_MAP_GET_NEXT_ID):
    assert_denied(bpf(BPF_MAP_GET_FD_BY_ID, IdAttr(map_id, 0, 0)),
                  f"writable fd for map {map_id}")
    assert_denied(bpf(BPF_MAP_GET_FD_BY_ID, IdAttr(map_id, 0, BPF_F_RDONLY)),
                  f"read-only fd for map {map_id}")
    maps += 1
if not maps:
    raise AssertionError("no map ids to try")

serializer_fd = -1
for prog_id in ids(BPF_PROG_GET_NEXT_ID):
    fd, error = bpf(BPF_PROG_GET_FD_BY_ID, IdAttr(prog_id, 0, 0))
    if fd < 0:
        continue
    info = ProgInfoPrefix()
    attr = ObjInfoAttr(fd, ctypes.sizeof(info), ctypes.addressof(info))
    result, error = bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    if result == 0 and info.name.startswith(b"shirudo_seriali"):
        serializer_fd = fd
        break
    os.close(fd)
if serializer_fd < 0:
    raise AssertionError("no serializer program found by id")
try:
    ctx = SerializerCtx(0x5A4C5253, 3, 0, 1, 4032, 0, 0, 1)
    attr = ProgTestRunAttr(serializer_fd, 0, 0, 0, 0, 0, 1, 0,
                           ctypes.sizeof(ctx), 0,
                           ctypes.addressof(ctx), 0, 0, 0, 0)
    result, error = bpf(BPF_PROG_TEST_RUN, attr)
    if result == 0 or error != errno.EACCES:
        raise AssertionError(
            f"serializer BPF_PROG_TEST_RUN: result={result}, errno={error}; "
            "expected LSM EACCES")
finally:
    os.close(serializer_fd)

output = os.path.join(sys.argv[3], "exec-after-test-run.ndjson")
subprocess.run([sys.argv[2], "upatch", "map", "kernel-obs", "exec",
                f"--json={output}"], check=True, stdout=subprocess.DEVNULL)
documents = [json.loads(line) for line in open(output, encoding="utf-8")]
records = [record for document in documents
           if isinstance(document, dict) and document.get("map") == "exec"
           for record in document.get("records", [])]
python_exe = os.path.realpath(sys.executable)
if not any(record.get("path") == python_exe for record in records):
    raise AssertionError(
        f"Python exec record was lost after denied serializer run: {records!r}")

print("root cannot open maps by pin, file or id; test-run denied; "
      "export preserved")
PYTHON

test_expect_success 'root cannot open maps or test-run a serializer' '
	"$SHIRUDO_BIN" upatch load "$LOAD" --no-precheck >/dev/null 2>&1 &&
	python3 "$WORK/check.py" "$MAPS" "$SHIRUDO_BIN" "$WORK"
'

test_done
