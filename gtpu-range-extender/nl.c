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
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>

// *
#include "shared.h"

#define NL_MSG_BUFLEN 4096

// grep _RTA\( /usr/include/linux/* 2>/dev/null| grep define
// /usr/include/linux/if_addr.h:#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
// /usr/include/linux/if_link.h:#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
// /usr/include/linux/rtnetlink.h:#define RTM_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
// /usr/include/linux/rtnetlink.h:#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))
// /usr/include/linux/rtnetlink.h:#define TA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcamsg))))

/* why tf do those not exist in the headers? */
#define NLA_DATA(nla) ((void *)((char *)(nla)) + NLA_HDRLEN)
#define NLA_LENGTH(len) (NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_RTA(r) ((struct nlattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))

static int tun_create(const char *devname) {
	int tun_fd, err;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_flags = (IFF_TUN | IFF_NO_PI);
	strncpy(ifr.ifr_name, devname, IFNAMSIZ);

	if ((tun_fd = open("/dev/net/tun", O_RDWR)) == -1) {
		perror("open tun");
		return tun_fd;
	}

	if ((err = ioctl(tun_fd, TUNSETIFF, (void *)&ifr)) == -1) {
		perror("TUNSETIFF - caps?");
		close(tun_fd);
		return err;
	}

	return tun_fd;
}

static int move_to_ns(int fd, int nsfd, const char *ifname) {
	char buf[NL_MSG_BUFLEN];
	memset(buf, 0, NL_MSG_BUFLEN);

	struct nlmsghdr *nl = (struct nlmsghdr *)buf;
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nl->nlmsg_type = RTM_NEWLINK;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct ifinfomsg *ifi = NLMSG_DATA(nl);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_nametoindex(ifname);
	ifi->ifi_type = 0;
	ifi->ifi_flags = 0;
	ifi->ifi_change = 0;

	struct nlattr *nla = NLA_RTA(ifi);
	nla->nla_type = IFLA_NET_NS_FD;
	nla->nla_len = NLA_LENGTH(sizeof(uint32_t));
	memcpy(NLA_DATA(nla), &(uint32_t){nsfd}, sizeof(uint32_t));
	nl->nlmsg_len = NLMSG_ALIGN(nl->nlmsg_len) + nla->nla_len;

	if (send(fd, nl, nl->nlmsg_len, MSG_NOSIGNAL) == -1) {
		perror("Failed to send Netlink message");
		// close(fd);
		return 1;
	}

	return 0;
}
/*
sendmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12, msg_iov=[{iov_base=[
{nlmsg_len=36, nlmsg_type=RTM_NEWROUTE, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE, nlmsg_seq=1722776151, nlmsg_pid=0},
{rtm_family=AF_INET, rtm_dst_len=0, rtm_src_len=0, rtm_tos=0, rtm_table=RT_TABLE_MAIN, rtm_protocol=RTPROT_BOOT, rtm_scope=RT_SCOPE_LINK, rtm_type=RTN_UNICAST,
rtm_flags=0},
[{nla_len=8, nla_type=RTA_OIF}, if_nametoindex("tun_c")]]

, iov_len=36}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 36

*/
static int add_rt(int fd, const char *ifname, const char *ip, int prefixlen, int rt_path_mtu, int defaultrt_flag) {
	int l;
	char buf[NL_MSG_BUFLEN];
	memset(buf, 0, NL_MSG_BUFLEN);

	struct nlmsghdr *nl = (struct nlmsghdr *)buf;
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE | NLM_F_ACK;
	nl->nlmsg_type = RTM_NEWROUTE;

	struct rtmsg *rtm;
	rtm = (struct rtmsg *)NLMSG_DATA(nl);
	rtm->rtm_family = AF_INET;
	rtm->rtm_table = RT_TABLE_MAIN;
	rtm->rtm_scope = RT_SCOPE_LINK;
	rtm->rtm_protocol = RTPROT_BOOT;
	rtm->rtm_type = RTN_UNICAST;
	rtm->rtm_dst_len = defaultrt_flag ? 0 : prefixlen;

#if 0
	struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm);
	rta->rta_type = RTA_DST;
	inet_pton(AF_INET, ip, RTA_DATA(rta));
	rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
	nl->nlmsg_len = NLMSG_ALIGN(nl->nlmsg_len) + rta->rta_len;


	int l = NL_MSG_BUFLEN - nl->nlmsg_len;
	rta = (struct rtattr *)RTA_NEXT(rta, l);
	rta->rta_type = RTA_OIF;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), &(uint32_t){if_nametoindex(ifname)}, sizeof(uint32_t));
	nl->nlmsg_len += rta->rta_len;
#endif
	struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm);
	rta->rta_type = RTA_OIF;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), &(uint32_t){if_nametoindex(ifname)}, sizeof(uint32_t));
	nl->nlmsg_len = NLMSG_ALIGN(nl->nlmsg_len) + rta->rta_len;

	if (!defaultrt_flag) {
		l = NL_MSG_BUFLEN - nl->nlmsg_len;
		rta = (struct rtattr *)RTA_NEXT(rta, l);
		rta->rta_type = RTA_DST;
		rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
		inet_pton(AF_INET, ip, RTA_DATA(rta));
		nl->nlmsg_len += rta->rta_len;
	}

#if 0
	l = NL_MSG_BUFLEN - nl->nlmsg_len;
	rta = (struct rtattr *)RTA_NEXT(rta, l);
	rta->rta_type = RTA_GATEWAY;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), data, data_length);
	nl->nlmsg_len += rta->rta_len;
#endif

	l = NL_MSG_BUFLEN - nl->nlmsg_len;
	struct rtattr *rta_cont = (struct rtattr *)RTA_NEXT(rta, l);
	rta_cont->rta_type = RTA_METRICS;
	rta_cont->rta_len = RTA_LENGTH(0);
	nl->nlmsg_len += rta->rta_len;

	if (rt_path_mtu != 0) {
		l = NL_MSG_BUFLEN - nl->nlmsg_len;
		rta = (struct rtattr *)RTA_NEXT(rta_cont, l);
		rta->rta_type = RTAX_MTU;
		rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
		memcpy(RTA_DATA(rta), &(uint32_t){rt_path_mtu}, sizeof(uint32_t));
		nl->nlmsg_len += rta->rta_len;
		rta_cont->rta_len += rta->rta_len;
	}

	l = NL_MSG_BUFLEN - nl->nlmsg_len;
	rta = (struct rtattr *)RTA_NEXT(rta_cont, l);
	rta->rta_type = RTAX_QUICKACK;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), &(uint32_t){1}, sizeof(uint32_t));
	nl->nlmsg_len += rta->rta_len;
	rta_cont->rta_len += rta->rta_len;

	assert(NLMSG_ALIGN(nl->nlmsg_len) == nl->nlmsg_len);
#if 0
	l = NL_MSG_BUFLEN - nl->nlmsg_len;
	rta = (struct rtattr *)RTA_NEXT(rta_cont, l);
	rta->rta_type = RTAX_QUICKACK;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), &(uint32_t){1}, sizeof(uint32_t));
	nl->nlmsg_len += rta->rta_len;
	rta_cont->rta_len += rta->rta_len;
#endif

	assert(NLMSG_ALIGN(nl->nlmsg_len) == nl->nlmsg_len);

	if (send(fd, nl, nl->nlmsg_len, MSG_NOSIGNAL) == -1) {
		perror("Failed to send Netlink message");
		// close(fd);
		return 1;
	}
	return 0;
}

static int add_ip(int fd, const char *ifname, const char *ip) {
	char buf[NL_MSG_BUFLEN];
	// int ip_len = 0;

	memset(buf, 0, NL_MSG_BUFLEN);

	struct nlmsghdr *nl;
	nl = (struct nlmsghdr *)buf;
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nl->nlmsg_type = RTM_NEWADDR;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct ifaddrmsg *ifa;
	ifa = (struct ifaddrmsg *)NLMSG_DATA(nl);
	ifa->ifa_family = AF_INET;
	ifa->ifa_prefixlen = 32; // 24;
	ifa->ifa_flags = IFA_F_PERMANENT;
	ifa->ifa_scope = 0;
	ifa->ifa_index = if_nametoindex(ifname);

	// pp: IFA_LOCAL is the if addr
	struct rtattr *rta = (struct rtattr *)IFA_RTA(ifa);
	rta->rta_type = IFA_LOCAL;
	inet_pton(AF_INET, ip, RTA_DATA(rta));
	rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
	nl->nlmsg_len = NLMSG_ALIGN(nl->nlmsg_len) + rta->rta_len;

// pp: IFA_ADDRESS is the peer/dest addr
#if 0
	int l = NL_MSG_BUFLEN - nl->nlmsg_len;
	rta = (struct rtattr *)RTA_NEXT(rta, l);
	rta->rta_type = IFA_ADDRESS;
	inet_pton(AF_INET, ip, RTA_DATA(rta));
	rta->rta_len = RTA_LENGTH(sizeof(struct in_addr));
	nl->nlmsg_len += rta->rta_len;
#endif

	if (send(fd, nl, nl->nlmsg_len, MSG_NOSIGNAL) == -1) {
		perror("Failed to send Netlink message");
		// close(fd);
		return 1;
	}
	return 0;
}

static int up_and_mtu(int fd, const char *ifname, int mtu) {
	char buf[NL_MSG_BUFLEN];
	memset(buf, 0, NL_MSG_BUFLEN);

	struct nlmsghdr *nl = (struct nlmsghdr *)buf;
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	nl->nlmsg_type = RTM_NEWLINK;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct ifinfomsg *ifi = NLMSG_DATA(nl);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_nametoindex(ifname);
	ifi->ifi_type = 0;
	ifi->ifi_flags = IFF_UP | IFF_NOARP;
	ifi->ifi_change = 0xffffffff;

	assert(NLMSG_ALIGN(nl->nlmsg_len) == nl->nlmsg_len);

	struct rtattr *rta = IFLA_RTA(ifi);
	rta->rta_type = IFLA_MTU;
	rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
	memcpy(RTA_DATA(rta), &(uint32_t){mtu}, sizeof(uint32_t));
	nl->nlmsg_len += rta->rta_len;

	assert(NLMSG_ALIGN(nl->nlmsg_len) == nl->nlmsg_len);

	if (send(fd, nl, nl->nlmsg_len, MSG_NOSIGNAL) == -1) {
		perror("Failed to send Netlink message");
		// close(fd);
		return 1;
	}
	return 0;
}

static int create_nl_sock(void) {
	int netlink_fd;
	struct sockaddr_nl sockaddr;
	if ((netlink_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) == -1) {
		perror("nl create fail");
		return netlink_fd;
	}

	setsockopt(netlink_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.nl_family = AF_NETLINK;
	// sockaddr.nl_pid = getpid(); let the kernel pick -> threading
	sockaddr.nl_groups = 0;

	if (bind(netlink_fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
		perror("nl bind fail");
		close(netlink_fd);
		return -1;
	}
	return netlink_fd;
}

static void read_nl_responses(int netlink_fd) {
	char nlbuf[4096];
	struct nlmsghdr *nlh = (struct nlmsghdr *)nlbuf;
	int len;
	sleep(1);
	// fcntl(netlink_fd, F_SETFL, fcntl(netlink_fd, F_GETFL, 0) | O_NONBLOCK);

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	setsockopt(netlink_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);


	while ((len = recv(netlink_fd, nlbuf, 4096, MSG_NOSIGNAL)) > 0) {
		nlh = (struct nlmsghdr *)nlbuf;
		while ((NLMSG_OK(nlh, (uint32_t)len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
				fprintf(stderr, "nl msg t %d -> ", err->msg.nlmsg_type);
				switch (err->error) {
					case 0: fprintf(stderr, "ok\n"); break;
					case -ENODEV: fprintf(stderr, "E: no dev?!\n"); break;
					default: fprintf(stderr, "%d: %s\n", err->error, strerror(err->error));
				}
			}
			// fprintf(stderr, "rx nl: %d\n", nlh->nlmsg_type);
			nlh = NLMSG_NEXT(nlh, len);
		}
	}
	fprintf(stderr, "done waiting for netlink msgs..\n");
}

static void print_all_if_idx(void) {
	struct if_nameindex *i, *if_ni;
	if ((if_ni = if_nameindex()) == NULL) {
		perror("if_nameindex ?!");
		return;
	}

	for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++)
		fprintf(stderr, "%u: %s\n", i->if_index, i->if_name);

	if_freenameindex(if_ni);
}

int set_tun_options(const char *ifname, const char *ip, const char *route, int rtprefix, int if_mtu, int route_path_mtu, int defroute, char *nsname) {

	int tun_fd, netlink_fd;
	int should_use_ns = (strlen(nsname) != 0);

	fprintf(stderr, "if list: \n");
	print_all_if_idx();

	if (should_use_ns && (enter_netns(nsname) < 0)) return -1;

	if ((tun_fd = tun_create(ifname)) < 0) return -1;

	char path[256];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);

    FILE* fp = fopen(path, "w");
    if (fp == NULL) {
        perror("failed to open sysctl...");
        return -1;
    }
    fprintf(fp, "1");
    fclose(fp);

	if ((netlink_fd = create_nl_sock()) < 0) return -1;

	// move_to_ns(netlink_fd, nsp.ns_fs, ifname);
	add_ip(netlink_fd, ifname, ip);
	up_and_mtu(netlink_fd, ifname, if_mtu);
	add_rt(netlink_fd, ifname, route, rtprefix, route_path_mtu, defroute);

	read_nl_responses(netlink_fd);
	close(netlink_fd);

	if (should_use_ns) {
		fprintf(stderr, "if list within ns: \n");
		print_all_if_idx();
		exit_netns();
	}

	return tun_fd;
}
