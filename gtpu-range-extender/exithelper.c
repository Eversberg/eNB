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
#include <unistd.h>
#include <sys/syscall.h>

void exit_group(int status);

__attribute__((noreturn)) void exit_group(int status) {
	syscall(SYS_exit_group, status);
	while(1);
}
