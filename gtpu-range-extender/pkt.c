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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

char *protocolNames[256] = {
		[IPPROTO_IP] = "IPv4", [IPPROTO_ICMP] = "ICMP", [IPPROTO_IGMP] = "IGMP", [IPPROTO_TCP] = "TCP",		[IPPROTO_UDP] = "UDP",	 [IPPROTO_RSVP] = "RSVP",
		[IPPROTO_GRE] = "GRE", [IPPROTO_ESP] = "ESP",		[IPPROTO_MTP] = "MTP",	 [IPPROTO_IPV6] = "IPv6", [IPPROTO_SCTP] = "SCTP", [IPPROTO_UDPLITE] = "UDPLITE",
};

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static void parse_headers(const unsigned char *packet, _UNU int len) {
	struct iphdr *ip_header = (struct iphdr *)packet;

	if (ip_header->version == 4) {
		// fdbg_printf("IPv4 packet\n");
		fdbg_printf("%s -> %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr), inet_ntoa(*(struct in_addr *)&ip_header->daddr));

		if (ip_header->protocol == IPPROTO_TCP) {
			_UNU struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
			fdbg_printf("TCP packet\n");
			fdbg_printf("Source Port: %u\n", ntohs(tcp_header->source));
			fdbg_printf("Destination Port: %u\n", ntohs(tcp_header->dest));
		} else if (ip_header->protocol == IPPROTO_UDP) {
			_UNU struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
			fdbg_printf("UDP packet\n");
			fdbg_printf("Source Port: %u\n", ntohs(udp_header->source));
			fdbg_printf("Destination Port: %u\n", ntohs(udp_header->dest));
		} else if (ip_header->protocol == IPPROTO_ICMP) {
			_UNU struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeof(struct iphdr));
			fdbg_printf("ICMP packet\n");
			fdbg_printf("Type: %u\n", icmp_header->type);
			fdbg_printf("Code: %u\n", icmp_header->code);
		}
	} else if (ip_header->version == 6) {
		struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;
		// fdbg_printf("IPv6 packet\n");
		char src_addr[INET6_ADDRSTRLEN], dst_addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ipv6_header->ip6_src, src_addr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ipv6_header->ip6_dst, dst_addr, INET6_ADDRSTRLEN);
		fdbg_printf("%s -> %s\n", src_addr, dst_addr);

		if (ipv6_header->ip6_nxt == IPPROTO_ICMPV6) {
			_UNU struct icmp6_hdr *icmpv6_header = (struct icmp6_hdr *)(packet + sizeof(struct ip6_hdr));
			fdbg_printf("ICMPv6 packet\n");
			fdbg_printf("Type: %u\n", icmpv6_header->icmp6_type);
			fdbg_printf("Code: %u\n", icmpv6_header->icmp6_code);
		}
	}
}

static void parse_packet(const unsigned char *packet, int len) {
	struct iphdr *ip_header = (struct iphdr *)packet;

	if (ip_header->version == 4) {
		fdbg_printf("IPv4 :: ");
		if (ip_header->protocol == IPPROTO_TCP) {
			fdbg_printf_nc("TCP\n");
		} else if (ip_header->protocol == IPPROTO_UDP) {
			fdbg_printf_nc("%UDP\n");
		} else if (ip_header->protocol == IPPROTO_ICMP) {
			fdbg_printf_nc("ICMP\n");
		} else {
			fdbg_printf_nc("Unknown\n");
		}
		parse_headers(packet, len);
	} else if (ip_header->version == 6) {
		fdbg_printf("IPv6 :: ");
		struct ip6_hdr *ipv6_header = (struct ip6_hdr *)packet;
		if (ipv6_header->ip6_nxt == IPPROTO_ICMPV6) {
			fdbg_printf_nc("ICMPv6\n");
		} else {
			fdbg_printf_nc("Unknown\n");
		}
		parse_headers(packet, len);
	} else {
		fdbg_printf("Unknown IP version\n");
	}
}

void print_packet_header(uint8_t *header) {
	// struct iphdr* hdr = (struct iphdr*)header;
	// uint8_t hdrt;
	// if (hdr->version != IPVERSION)
	// 	hdrt = header[offsetof(struct ip6_hdr, ip6_ctlun.ip6_un1.ip6_un1_nxt)];
	// else
	// 	hdrt = header[offsetof(struct iphdr, protocol)];

	// const char* protocolName = protocolNames[hdrt];

	// if (protocolName != NULL) {
	// 	fdbg_printf("Protocol: %s\n", protocolName);
	// } else {
	// 	fdbg_printf("Unknown protocol %d\n", hdrt);
	// }
	parse_packet(header, 1234);
}
