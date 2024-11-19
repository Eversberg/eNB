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

#include "shared.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct __attribute__((packed)) {
	uint8_t flags;
	uint8_t type;
	uint16_t len;
	uint32_t teid;
	// uint16_t sqn;
} gtp_hdr;

static int gtp_fd;
static uint32_t global_dst_addr;
static uint32_t global_teid;

static __thread char str_src[INET6_ADDRSTRLEN];
static __thread char str_dst[INET6_ADDRSTRLEN];
struct sockaddr_in server_pars;

int init_gtp_sock(uint32_t saddr, uint32_t dstaddr, uint32_t teid) {

	if ((gtp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)) == -1) {
		perror("gtp socket");
		exit(1);
	}
	setsockopt(gtp_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	server_pars.sin_family = AF_INET;
	server_pars.sin_addr.s_addr = saddr; // inet_addr(enb_gtpaddr);
	server_pars.sin_port = htons(2152);

	if ((bind(gtp_fd, (const struct sockaddr*)&server_pars, sizeof(server_pars))) == -1) {
		perror("gtp bind");
		exit(1);
	}
	global_dst_addr = dstaddr;
	global_teid = teid;
	return gtp_fd;
}

int txgtp(uint8_t* data, int datalen) {
	struct sockaddr_storage dst_addr;
	gtp_hdr gtp_header = {.flags = 0x30, .type = 0xff, .len = htons(datalen), .teid = global_teid};
	struct iovec snd_iov[2];
	snd_iov[0].iov_base = &gtp_header;
	snd_iov[0].iov_len = sizeof(gtp_header);
	snd_iov[1].iov_base = data;
	snd_iov[1].iov_len = datalen;

	struct sockaddr_in* dsta = ((struct sockaddr_in*)&dst_addr);
	dsta->sin_family = AF_INET;
	dsta->sin_addr.s_addr = global_dst_addr;
	dsta->sin_port = htons(2152);

	struct msghdr snd_msg = {.msg_iov = snd_iov, .msg_iovlen = 2, .msg_name = &dst_addr, .msg_namelen = sizeof(dst_addr), .msg_flags = MSG_NOSIGNAL};
	int sent;
	if ((sent = sendmsg(gtp_fd, &snd_msg, MSG_NOSIGNAL)) == -1) {
		perror("gtp sendmsg");
		close(gtp_fd);
		exit(1);
	}

	inet_ntop(AF_INET, &server_pars.sin_addr.s_addr, str_src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET, &dsta->sin_addr.s_addr, str_dst, INET6_ADDRSTRLEN);
	fdbg_printf("sent %d %d : %s:%d <-> %s:%d\n", sent, sent, str_src, ntohs(server_pars.sin_port), str_dst, ntohs(dsta->sin_port));
	print_packet_header(data);

	return sent;
}

static union {
	gtp_hdr hdr;
	uint8_t rx_pktbuf[4096];
} rxbuf;

int rxgtp(uint8_t** data) {
	struct sockaddr_storage src_addr;
	struct iovec rcv_iov = {.iov_base = rxbuf.rx_pktbuf, .iov_len = sizeof(rxbuf.rx_pktbuf)};
	struct msghdr rcv_msg = {.msg_iov = &rcv_iov, .msg_iovlen = 1, .msg_name = &src_addr, .msg_namelen = sizeof(src_addr), .msg_flags = MSG_NOSIGNAL};
	int rcvd;

	if ((rcvd = recvmsg(gtp_fd, &rcv_msg, MSG_NOSIGNAL)) == -1) {
		perror("recvmsg");
		close(gtp_fd);
		exit(1);
	}

	// if(gtp_header->type == 0x01){
	//     gtp_header->type = 0x02;
	// }
	// if (gtp_header->flags & 0x02) // sqn

	*data = &rxbuf.rx_pktbuf[8];
	if (rxbuf.hdr.flags == 0x30 && rxbuf.hdr.type == 0xff) {
		struct sockaddr_in* rxh = (struct sockaddr_in*)rcv_msg.msg_name;
		inet_ntop(AF_INET, &server_pars.sin_addr.s_addr, str_dst, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &rxh->sin_addr.s_addr, str_src, INET6_ADDRSTRLEN);
		fdbg_printf("received %d %d : %s:%d <-> %s:%d\n", rcvd, rcvd, str_src, ntohs(server_pars.sin_port), str_dst, ntohs(rxh->sin_port));
		print_packet_header(*data);
		return rcvd - 8;
	}

	return 0;
}
