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

#include <arpa/inet.h>
#include <assert.h>
#include <bits/getopt_core.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/syscall.h>

// #define DO_DEV 1
#include "shared.h"


__thread char threadn[20];
__thread int threadn_color;
__thread int threadn_par_color;

static volatile int do_exit = 0;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void int_h(int nop) { do_exit = 1; }
#pragma GCC diagnostic pop

#define BUFFER_SIZE 4096

typedef struct __attribute__((packed)) {
	uint16_t length;
	uint8_t flags;
} pkt_hdr;

typedef struct __attribute__((packed)) {
	uint32_t addr;
	uint32_t route;
	uint32_t rt_prefix;
	uint32_t if_mtu;
	uint32_t path_mtu;
	uint32_t defaulrt_flag;
} cfg_options;

typedef struct {
	uint32_t enb_addr;
	uint32_t gtpu_addr;
	uint32_t client_addr;
	uint32_t client_route;
	uint32_t client_route_len;
	uint32_t teid;
	uint32_t dev_max_transf_sz;
	char netns_name[20];
	uint32_t defaulrt_flag;
} global_args;

global_args globs;

static ssize_t safe_recv(int sockfd, uint8_t *buf, size_t len, int flags) {
	ssize_t ret;
	while ((ret = recv(sockfd, buf, len, flags)) == -1) {
		if (errno == EINTR || errno == EAGAIN) { continue; }
		break;
	}
	// fdbg_printf("saferecv %zd\n", ret);
	return ret;
}

#define PKT_END_FLAG (1 << 0UL)
#define PKT_START_FLAG (1 << 1UL)
#define PKT_CONF_FLAG (1 << 2UL)

static void send_chunked(int sockfd, uint8_t *data, size_t dataSize, size_t MAX_TRANSFER_SIZE) {
	uint8_t *data_ptr = data;
	int startflag = PKT_START_FLAG;
	const size_t max_sz_with_header = MAX_TRANSFER_SIZE - sizeof(pkt_hdr);
	assert(MAX_TRANSFER_SIZE > sizeof(pkt_hdr));

	if (!dataSize) return;

	while (dataSize > 0) {
		ssize_t bytesSent;
		int endflag = dataSize > max_sz_with_header ? 0 : PKT_END_FLAG;
		size_t cur_trans_sz = dataSize > max_sz_with_header ? max_sz_with_header : dataSize;
		pkt_hdr hdr = {.length = htons(cur_trans_sz), .flags = 0x00 | endflag | startflag};
		startflag = 0;
#if 1
		struct iovec snd_iov[2] = {{.iov_base = &hdr, .iov_len = sizeof(hdr)}, {.iov_base = data_ptr, .iov_len = cur_trans_sz}};
		// snd_iov[0].iov_base = &hdr;
		// snd_iov[0].iov_len = sizeof(hdr);
		// snd_iov[1].iov_base = data_ptr;
		// snd_iov[1].iov_len = cur_trans_sz;

		struct msghdr snd_msg = {.msg_iov = snd_iov, .msg_iovlen = 2, .msg_flags = MSG_NOSIGNAL};

		if ((bytesSent = sendmsg(sockfd, &snd_msg, MSG_NOSIGNAL)) == -1) {
			perror("Error sending data");
			exit_group(EXIT_FAILURE);
		}
#else
		bytesSent = send(sockfd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
		if (bytesSent == -1) {
			perror("Error sending header");
			exit_group(EXIT_FAILURE);
		}

		bytesSent = send(sockfd, data_ptr, cur_trans_sz, MSG_NOSIGNAL);
		if (bytesSent == -1) {
			perror("Error sending data");
			exit_group(EXIT_FAILURE);
		}
#endif
		fdbg_printf("sent %zd %zd %d\n", bytesSent, cur_trans_sz, hdr.flags);

		dataSize -= cur_trans_sz;
		data_ptr += cur_trans_sz;
	}
	print_packet_header(data);
}

static int read_from_tcp_socket(int sockfd, uint8_t *buffer) {
	int bufptr = 0, ret = -1;
	ssize_t n;
	union {
		pkt_hdr hdr;
		uint8_t d[sizeof(pkt_hdr)];
	} hdr;
	_Static_assert(sizeof(hdr) == sizeof(pkt_hdr), "misaligned hdr?");

	while ((n = safe_recv(sockfd, &hdr.d[0], sizeof(hdr.hdr), MSG_WAITALL | MSG_NOSIGNAL)) > 0) {
		hdr.hdr.length = ntohs(hdr.hdr.length);

		// assert(hdr.hdr.flags & PKT_START_FLAG && bufptr == 0);

		if (hdr.hdr.flags & PKT_START_FLAG && bufptr != 0) {
			perror("Error start/buf ptr");
			fprintf(stderr, "%d %d %d\n", hdr.hdr.flags, hdr.hdr.length, bufptr);
			exit_group(EXIT_FAILURE);
		}
		if (hdr.hdr.length + bufptr >= BUFFER_SIZE) {
			perror("Error buf ptr");
			exit_group(EXIT_FAILURE);
		}

		n = safe_recv(sockfd, &buffer[bufptr], hdr.hdr.length, MSG_WAITALL | MSG_NOSIGNAL);
		if (n == -1 && errno != EAGAIN) {
			perror("Error reading flags");
			exit_group(EXIT_FAILURE);
		}
		bufptr += n;
		ret = bufptr;

		if (hdr.hdr.flags & PKT_END_FLAG
				// && hdr.hdr.flags & PKT_START_FLAG
		) {
			fdbg_printf("done rcv! %d\n", bufptr);
			print_packet_header(buffer);
			bufptr = 0;
			return ret;
		}
		// fdbg_printf("flags: %d\n", hdr.hdr.flags);

		// Handle reassembly logic here
	}

	perror("Error reading data");
	exit_group(EXIT_FAILURE);
	return 0;

	// if (n == -1 && errno != EAGAIN) {
	//     perror("Error reading data");
	//     exit_group(EXIT_FAILURE);
	// }
}

typedef struct {
	int tunfd;
	int devfd;
	uint32_t teid;
	char name[10];
	int par_color;
} handler_args;

static void *t_t2dev(void *a) {
	uint8_t buffer[BUFFER_SIZE];
	ssize_t n;
	handler_args *args = (handler_args *)a;
	strncpy(threadn, args->name, 10);
	threadn_color = YELLOW;
	threadn_par_color = args->par_color;

	while ((n = read(args->tunfd, &buffer[0], BUFFER_SIZE)) > 0) {
		send_chunked(args->devfd, &buffer[0], n, globs.dev_max_transf_sz);
	}
	fdbg_printf("exit t2d: %zd\n", n);
	return 0;
}

static void *t_dev2t(void *a) {
	uint8_t buffer[BUFFER_SIZE];
	ssize_t n;
	handler_args *args = (handler_args *)a;
	strncpy(threadn, args->name, 10);
	threadn_color = BLUE;
	threadn_par_color = args->par_color;

	while ((n = read_from_tcp_socket(args->devfd, &buffer[0])) > 0) {
		int r = write(args->tunfd, buffer, n);
		if (r != n) {
			perror("Error reading data");
			fdbg_printf("exit d2t: %d != %zd\n", r, n);
		}
	}
	fdbg_printf("exit d2t: %zd\n", n);
	return 0;
}

static void *t_gtp2t(void *a) {
	ssize_t n;
	handler_args *args = (handler_args *)a;
	strncpy(threadn, args->name, 10);
	threadn_color = MAGENTA;
	threadn_par_color = args->par_color;
	uint8_t *data;

	while ((n = rxgtp(&data)) >= 0) {
		send_chunked(args->devfd, data, n, globs.dev_max_transf_sz);
	}
	fdbg_printf("exit t2d: %zd\n", n);
	return 0;
}

static void *t_t2gtp(void *a) {
	uint8_t buffer[BUFFER_SIZE];
	ssize_t n;
	handler_args *args = (handler_args *)a;
	strncpy(threadn, args->name, 10);
	threadn_color = CYAN;
	threadn_par_color = args->par_color;

	while ((n = read_from_tcp_socket(args->devfd, &buffer[0])) > 0) {
		int r = txgtp(buffer, n);
		if (r < n) { // gtp header!
			perror("Error reading data");
			fdbg_printf("exit d2t: %d != %zd\n", r, n);
		}
	}
	fdbg_printf("exit d2t: %zd\n", n);
	return 0;
}

static void *server_thread(_UNU void* arg) {
	int ret;
	int server_sock, client_sock;
	strncpy(threadn, "srv", 10);
	threadn_color = RED;

	socket_or_die(server_sock, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	struct sockaddr_in server_pars, client;
	server_pars.sin_family = AF_INET;
	server_pars.sin_addr.s_addr = globs.enb_addr; // inet_addr("127.0.0.3"); // INADDR_ANY;
	server_pars.sin_port = htons(8888);
	bind_or_die(server_sock, server_pars);
	listen_or_die(server_sock, 20);
	// nb_or_die(server_sock);

	client_sock = accept(server_sock, (struct sockaddr *)&client, &(socklen_t){1});
	if (client_sock < 0) {
		perror("accept failed");
		return (void *)1;
	}

	setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

#if DO_DEV
	int tun_fd = set_tun_options("tun_s", "172.0.0.2", "172.0.0.3", 32, 1234, 0, "");
#endif
	{
		cfg_options opt = {0};
		pkt_hdr hdr = {.length = htons(sizeof(opt)), .flags = 0x00 | PKT_END_FLAG | PKT_START_FLAG | PKT_CONF_FLAG};

		// struct in_addr tmpa;
		// inet_aton("172.0.0.3", &tmpa);
		// opt.addr = tmpa.s_addr;
		opt.addr = globs.client_addr;
		// inet_aton("172.0.0.2", &tmpa);
		// opt.route = tmpa.s_addr;
		opt.route = globs.client_route;
		opt.rt_prefix = globs.client_route_len;
		opt.if_mtu = 1358;
		opt.defaulrt_flag = globs.defaulrt_flag;

		struct iovec data[2];
		data[0].iov_base = &hdr;
		data[0].iov_len = sizeof(hdr);
		data[1].iov_base = &opt;
		data[1].iov_len = sizeof(opt);
		_UNU int r = writev(client_sock, data, 2);

		// send(client_sock, &hdr, sizeof(hdr), MSG_NOSIGNAL);
		// send(client_sock, &opt, sizeof(opt), MSG_NOSIGNAL);

		fdbg_printf("%d, %x -> %x :: %d\n", r, opt.addr, opt.route, opt.rt_prefix);
	}

#if DO_DEV
	pthread_t t2dev, dev2t;
	handler_args a = {.devfd = client_sock, .tunfd = tun_fd};
	handler_args b = {.devfd = client_sock, .tunfd = tun_fd};
	sprintf(a.name, "s_t2d");
	pthread_create(&t2dev, NULL, t_t2dev, (void *)&a);
	sprintf(b.name, "s_d2t");
	pthread_create(&dev2t, NULL, t_dev2t, (void *)&b);
#else
	int gtp_fd = init_gtp_sock(globs.enb_addr, globs.gtpu_addr, globs.teid);
	pthread_t t2dev, dev2t;
	handler_args a = {.devfd = client_sock, .tunfd = gtp_fd, .teid = globs.teid, .par_color = threadn_color};
	handler_args b = {.devfd = client_sock, .tunfd = gtp_fd, .teid = globs.teid, .par_color = threadn_color};
	sprintf(a.name, "s_t2d");
	pthread_create(&t2dev, NULL, t_t2gtp, (void *)&a);
	sprintf(b.name, "s_d2t");
	pthread_create(&dev2t, NULL, t_gtp2t, (void *)&b);
#endif
	pthread_join(t2dev, NULL);
	pthread_join(dev2t, NULL);

	return EXIT_SUCCESS;
}

static void *client_thread(_UNU void* arg) {
	int sock;
	struct sockaddr_in server;
	strncpy(threadn, "cln", 10);
	threadn_color = GREEN;

	socket_or_die(sock, AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

#if 0
	setsockopt(sock, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &(int){1}, sizeof(int));
	server.sin_addr.s_addr = inet_addr("127.0.0.3");
	server.sin_family = AF_INET;
	server.sin_port = 0;
	if (bind(sock, (const struct sockaddr *)&server, sizeof(server)) == -1) {
		perror("bind");
		return (void *)EXIT_FAILURE;
	}
#endif

	server.sin_addr.s_addr = globs.enb_addr; // inet_addr("127.0.0.3");
	server.sin_family = AF_INET;
	server.sin_port = htons(8888);


    // struct timeval timeout;
    // timeout.tv_sec = 2;
    // timeout.tv_usec = 0;

    // PERR_LT0_EXIT(setsockopt (sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,sizeof(struct timeval)));
    // PERR_LT0_EXIT(setsockopt (sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof (struct timeval)));

	// PERR_LT0_EXIT(setsockopt(sock, IPPROTO_TCP , TCP_USER_TIMEOUT, &(int){5000}, sizeof(int)))
	// PERR_LT0_EXIT(setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, &(int){2}, sizeof(int)));


 	PERR_LT0_EXIT(setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &(int){1}, sizeof(int)));
	PERR_LT0_EXIT(setsockopt(sock, IPPROTO_TCP , TCP_USER_TIMEOUT, &(int){5000}, sizeof(int)))

	PERR_LT0_EXIT(setsockopt(sock, IPPROTO_TCP , TCP_KEEPIDLE, &(int){1}, sizeof(int)))
	PERR_LT0_EXIT(setsockopt(sock, IPPROTO_TCP , TCP_KEEPINTVL, &(int){5}, sizeof(int)))
	PERR_LT0_EXIT(setsockopt(sock, IPPROTO_TCP , TCP_KEEPCNT, &(int){3}, sizeof(int)))


	PERR_LT0_EXIT(connect(sock, (struct sockaddr *)&server, sizeof(server)));

	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

	char addrbuf[32] = {0};
	char rtbuf[32] = {0};

	uint8_t opt_buf[sizeof(pkt_hdr) + sizeof(cfg_options)];

	if (safe_recv(sock, &opt_buf[0], sizeof(pkt_hdr) + sizeof(cfg_options), MSG_WAITALL | MSG_NOSIGNAL) > 0) {
		pkt_hdr *p = (pkt_hdr *)opt_buf;
		p->length = ntohs(p->length);
		assert(p->length == sizeof(cfg_options));
		assert(p->flags == (PKT_START_FLAG | PKT_END_FLAG | PKT_CONF_FLAG));
	} else {
		perror("wtf, opt failure?");
		exit_group(1);
	}

	cfg_options *o = (cfg_options *)(&opt_buf[0] + sizeof(pkt_hdr));
	inet_ntop(AF_INET, &o->addr, addrbuf, sizeof(addrbuf));
	inet_ntop(AF_INET, &o->route, rtbuf, sizeof(rtbuf));

	fdbg_printf("%s -> %s :: %d\n", addrbuf, rtbuf, o->rt_prefix);
	fprintf(stderr, "###\nsetting defroute flag = %d \n###\n", o->defaulrt_flag);

	int tun_fd = set_tun_options("tun_c", addrbuf, rtbuf, o->rt_prefix, o->if_mtu, 0, globs.defaulrt_flag, globs.netns_name);

	pthread_t t2dev, dev2t;
	handler_args a = {.devfd = sock, .tunfd = tun_fd, .par_color = threadn_color};
	handler_args b = {.devfd = sock, .tunfd = tun_fd, .par_color = threadn_color};
	sprintf(a.name, "c_t2d");
	pthread_create(&t2dev, NULL, t_t2dev, (void *)&a);
	sprintf(b.name, "c_d2t");
	pthread_create(&dev2t, NULL, t_dev2t, (void *)&b);

	pthread_join(t2dev, NULL);
	pthread_join(dev2t, NULL);

	return 0;
}

static uint32_t handle_ipa_arg(char *arg) {
	unsigned char buf[sizeof(struct in6_addr)];
	int s;
	if ((s = inet_pton(AF_INET, arg, buf)) <= 0) {
		if (s == 0)
			fprintf(stderr, "??");
		else
			perror("inet_pton");
		return 1;
	}
	return ((struct in_addr *)buf)->s_addr;
}

static int print_proper_addresses(void) {
	char str_gtp[INET6_ADDRSTRLEN];
	char str_enb[INET6_ADDRSTRLEN];
	char str_client[INET6_ADDRSTRLEN];
	char str_route[INET6_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &globs.gtpu_addr, str_gtp, INET6_ADDRSTRLEN) == NULL) {
		perror("ntop");
		return 1;
	}
	if (inet_ntop(AF_INET, &globs.enb_addr, str_enb, INET6_ADDRSTRLEN) == NULL) {
		perror("ntop");
		return 1;
	}
	if (inet_ntop(AF_INET, &globs.client_addr, str_client, INET6_ADDRSTRLEN) == NULL) {
		perror("ntop");
		return 1;
	}
	if (inet_ntop(AF_INET, &globs.client_route, str_route, INET6_ADDRSTRLEN) == NULL) {
		perror("ntop");
		return 1;
	}

	fprintf(stderr, "enb addr: %s\ngtp-u addr: %s\nclient addr: %s\nclient route: %s\nclient rtlen: %d\nteid: %x (%u)\nnsname: %s\n", str_enb, str_gtp,
					str_client, str_route, globs.client_route_len, ntohl(globs.teid), ntohl(globs.teid), globs.netns_name);

	return 0;
}

static int parse_opts(int argc, char *argv[]) {
	int opt;
	while ((opt = getopt(argc, argv, "e:g:c:r:p:t:n:d")) != -1) {
		switch (opt) {
			case 'e': globs.enb_addr = handle_ipa_arg(optarg); break;
			case 'g': globs.gtpu_addr = handle_ipa_arg(optarg); break;
			case 'c': globs.client_addr = handle_ipa_arg(optarg); break;
			case 'r': globs.client_route = handle_ipa_arg(optarg); break;
			case 'p': globs.client_route_len = strtoul(optarg, NULL, 10); break;
			case 't': globs.teid = htonl(strtoul(optarg, NULL, 10)); break;
			case 'n': strncpy(globs.netns_name, optarg, sizeof(globs.netns_name)-1); break;
			case 'd': globs.defaulrt_flag = 1; break;
			default: fprintf(stderr, "Usage: %s \n", argv[0]); exit_group(EXIT_FAILURE);
		}
	}
	return 0;
}

#if !defined(DO_B_C) && !defined(DO_B_S)
int main(int argc, char *argv[]) {
	pthread_t listener, handler;

	if (argc < 7) {
		fprintf(stderr,
						"%s e:g:c:r:p:t:n:d -> -e <local enb-addr> -g <remote gtpu-addr> -c <assigned client addr> -r <client route> -p <client route len> -t <teid> -n "
						"[netnsname] -d [defroute_client]\n",
						argv[0]);
		fprintf(stderr, "ex: %s 192.168.0.11 172.1.2.3 10.0.0.3 10.0.0.0 24 123456 enb_client 1\n", argv[0]);
		return 1;
	}

	parse_opts(argc, argv);
	globs.dev_max_transf_sz = 1400;

	// signal(SIGPIPE, SIG_IGN);
	// signal(SIGINT, int_h);

	pthread_create(&listener, NULL, server_thread, NULL);
	pthread_create(&handler, NULL, client_thread, NULL);

	pthread_join(listener, NULL);
	pthread_join(handler, NULL);
}
#endif

#ifdef DO_B_C
int main(int argc, char *argv[]) {
	// pthread_t listener, handler;
	// char str_gtp[INET6_ADDRSTRLEN];
	char str_enb[INET6_ADDRSTRLEN];
	// char str_client[INET6_ADDRSTRLEN];
	// char str_route[INET6_ADDRSTRLEN];

	if (argc < 2) {
		fprintf(stderr, "%s <rem server addr> [nsname]\n", argv[0]);
		fprintf(stderr, "ex: %s 192.168.0.11 bernd\n", argv[0]);
		return 1;
	}

	globs.dev_max_transf_sz = 1400;
	parse_opts(argc, argv);

	fprintf(stderr, "enb addr: %s\nnsname: %s\n", str_enb, globs.netns_name);

	// signal(SIGPIPE, SIG_IGN);
	// signal(SIGINT, int_h);

	client_thread(0);
}
#endif

#ifdef DO_B_S
int main(int argc, char *argv[]) {
	// pthread_t listener, handler;

	if (argc < 7) {
		fprintf(stderr,
						"%s e:g:c:r:p:t:n:d -> -e <local enb-addr> -g <remote gtpu-addr> -c <assigned client addr> -r <client route> -p <client route len> -t <teid> -n -d"
						"[netnsname] -d [defroute_client]\n",
						argv[0]);
		// fprintf(stderr, "ex: %s 192.168.0.11 172.1.2.3 10.0.0.3 10.0.0.0 24 123456 enb_client\n", argv[0]);
		return 1;
	}

	globs.dev_max_transf_sz = 1400;
	parse_opts(argc, argv);
	if (print_proper_addresses() != 0) exit_group(1);

	// signal(SIGPIPE, SIG_IGN);
	// signal(SIGINT, int_h);

	server_thread(0);
	// pthread_create(&listener, NULL, server_thread, NULL);
	// pthread_create(&handler, NULL, client_thread, NULL);

	// pthread_join(listener, NULL);
	// pthread_join(handler, NULL);
}
#endif