/*
 * (C) 2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Eric Wild <ewild@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define _GNU_SOURCE
#include <sched.h>
#undef _GNU_SOURCE

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "shared.h"

typedef struct {
	int good;
	int ns_fs;
	int original_ns_fd;
} netns_parms;

__thread netns_parms nspar;

int enter_netns(const char *nsname) {
	netns_parms rp = {0};
	char nspath[250] = {0};
	int nsfd, old_ns_fd, ns_res;
	nspar = rp;
	snprintf(nspath, sizeof(nspath), "/run/netns/%s", nsname);

	if (nspar.good) {
		perror("refusing to enter ns twice...");
		return -1;
	}

	if ((nsfd = openat(AT_FDCWD, nspath, O_RDONLY)) < 0) {
		perror("ns does not exist?");
		return -1;
	}

	if ((old_ns_fd = open("/proc/self/ns/net", O_RDONLY)) < 0) {
		perror("old ns does not exist????");
		return -1;
	}

	if ((ns_res = setns(nsfd, CLONE_NEWNET)) < 0) {
		perror("ns enter error");
		return -1;
	}

	rp.ns_fs = nsfd;
	rp.original_ns_fd = old_ns_fd;
	rp.good = 1;
	nspar = rp;
	return 1;
}

void exit_netns(void) {
	int ns_res;

	if (!nspar.good) return;
	if ((ns_res = setns(nspar.original_ns_fd, CLONE_NEWNET)) < 0) {
		perror("ns enter to exit error?!");
		// exit(1);
	}
	close(nspar.ns_fs);
	close(nspar.original_ns_fd);
}