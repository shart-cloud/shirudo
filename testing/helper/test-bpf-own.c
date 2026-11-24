// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a root process that is not shirudo may do with bpf() on a target
 * under bpf.enforcement = own. Each subcommand prints "ok" or
 * "errno=<n>" for the step the test asserts on.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>

/* r0 = 0; exit */
static const struct bpf_insn return_zero[] = {
	{ .code = 0xb7, .dst_reg = 0, .imm = 0 },
	{ .code = 0x95 },
};

static int report(int ret)
{
	if (ret < 0)
		printf("errno=%d\n", -ret);
	else
		printf("ok\n");
	return 0;
}

static int load(enum bpf_prog_type type, struct bpf_prog_load_opts *opts)
{
	int fd;

	fd = bpf_prog_load(type, NULL, "GPL", return_zero,
			   ARRAY_SIZE(return_zero), opts);
	return fd < 0 ? -errno : fd;
}

/* An unsigned socket filter, loaded and run, and its descriptor by id. */
static int own_program(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, run, .data_in = "packet",
		    .data_size_in = 6);
	struct bpf_prog_info info = {};
	__u32 length = sizeof(info);
	int fd, again, ret;

	fd = load(BPF_PROG_TYPE_SOCKET_FILTER, NULL);
	if (fd < 0)
		return fd;
	ret = bpf_prog_test_run_opts(fd, &run) ? -errno : 0;
	if (!ret && bpf_prog_get_info_by_fd(fd, &info, &length))
		ret = -errno;
	if (!ret) {
		again = bpf_prog_get_fd_by_id(info.id);
		ret = again < 0 ? -errno : 0;
		if (again >= 0)
			close(again);
	}
	close(fd);
	return ret;
}

/* A hash map of the caller's own: created, written, pinned and opened. */
static int own_map(const char *pin)
{
	__u32 key = 1, value = 2;
	int fd, again, ret = 0;

	fd = bpf_map_create(BPF_MAP_TYPE_HASH, "own_test", sizeof(key),
			    sizeof(value), 4, NULL);
	if (fd < 0)
		return -errno;
	if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) ||
	    bpf_map_delete_elem(fd, &key) || bpf_obj_pin(fd, pin))
		ret = -errno;
	close(fd);
	if (ret)
		return ret;
	again = bpf_obj_get(pin);
	if (again < 0)
		return -errno;
	close(again);
	return unlink(pin) ? -errno : 0;
}

/* A map of the caller's own, pinned where pin names. */
static int pin_map(const char *pin)
{
	int fd, ret;

	fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "own_pin", sizeof(__u32),
			    sizeof(__u32), 1, NULL);
	if (fd < 0)
		return -errno;
	ret = bpf_obj_pin(fd, pin) ? -errno : 0;
	close(fd);
	return ret;
}

static int lsm_program(void)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		    .expected_attach_type = BPF_LSM_MAC);
	struct btf *vmlinux;
	int id, fd;

	vmlinux = btf__load_vmlinux_btf();
	if (!vmlinux)
		return -errno;
	id = btf__find_by_name_kind(vmlinux, "bpf_lsm_file_open",
				    BTF_KIND_FUNC);
	btf__free(vmlinux);
	if (id <= 0)
		return -ENOENT;
	opts.attach_btf_id = id;
	fd = load(BPF_PROG_TYPE_LSM, &opts);
	if (fd >= 0)
		close(fd);
	return fd < 0 ? fd : 0;
}

/* The descriptors of every object of one kind, by id: how many opened. */
static int scan(const char *kind)
{
	int (*next)(__u32 start, __u32 *next_id);
	int (*get)(__u32 id);
	__u32 opened = 0, refused = 0;
	__u32 id = 0;
	int fd;

	if (!strcmp(kind, "prog")) {
		next = bpf_prog_get_next_id;
		get = bpf_prog_get_fd_by_id;
	} else if (!strcmp(kind, "map")) {
		next = bpf_map_get_next_id;
		get = bpf_map_get_fd_by_id;
	} else if (!strcmp(kind, "link")) {
		next = bpf_link_get_next_id;
		get = bpf_link_get_fd_by_id;
	} else {
		return 2;
	}
	while (!next(id, &id)) {
		fd = get(id);
		if (fd >= 0) {
			opened++;
			close(fd);
		} else if (errno == EACCES) {
			refused++;
		}
	}
	printf("opened=%u refused=%u\n", opened, refused);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "program"))
		return report(own_program());
	if (argc == 3 && !strcmp(argv[1], "map"))
		return report(own_map(argv[2]));
	if (argc == 3 && !strcmp(argv[1], "pin"))
		return report(pin_map(argv[2]));
	if (argc == 3 && !strcmp(argv[1], "get")) {
		int fd = bpf_obj_get(argv[2]);

		if (fd >= 0)
			close(fd);
		return report(fd < 0 ? -errno : 0);
	}
	if (argc == 2 && !strcmp(argv[1], "lsm"))
		return report(lsm_program());
	if (argc == 2 && !strcmp(argv[1], "loader")) {
		int fd = load(BPF_PROG_TYPE_SYSCALL, NULL);

		if (fd >= 0)
			close(fd);
		return report(fd < 0 ? fd : 0);
	}
	if (argc == 3 && !strcmp(argv[1], "scan"))
		return scan(argv[2]);
	fprintf(stderr, "usage: %s program | map <pin> | pin <pin> | "
		"get <pin> | lsm | loader | scan prog|map|link\n", argv[0]);
	return 2;
}
