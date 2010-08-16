/*
 *   Copyright (C) 2010 Felix Fietkau <nbd@openwrt.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License v2 as published by
 *   the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "relayd.h"

struct ip_packet {
	struct ether_header eth;
	struct iphdr iph;
} __packed;

struct dhcp_header {
	uint8_t op, htype, hlen, hops;
	uint32_t xit;
	uint16_t secs, flags;
	struct in_addr ciaddr, yiaddr, siaddr, giaddr;
	unsigned char chaddr[16];
	unsigned char sname[64];
	unsigned char file[128];
} __packed;

static uint16_t
chksum(uint16_t sum, const uint8_t *data, uint16_t len)
{
	const uint8_t *last;
	uint16_t t;

	last = data + len - 1;

	while(data < last) {
		t = (data[0] << 8) + data[1];
		sum += t;
		if(sum < t)
			sum++;
		data += 2;
	}

	if(data == last) {
		t = (data[0] << 8) + 0;
		sum += t;
		if(sum < t)
			sum++;
	}

	return sum;
}

bool relayd_handle_dhcp_packet(struct relayd_interface *rif, void *data, int len, bool forward)
{
	struct ip_packet *pkt = data;
	struct udphdr *udp;
	struct dhcp_header *dhcp;
	int udplen;
	uint16_t sum;

	if (pkt->eth.ether_type != htons(ETH_P_IP))
		return false;

	if (pkt->iph.version != 4)
		return false;

	if (pkt->iph.protocol != IPPROTO_UDP)
		return false;

	udp = (void *) ((char *) &pkt->iph + (pkt->iph.ihl << 2));
	dhcp = (void *) (udp + 1);

	udplen = ntohs(udp->len);
	if (udplen > len - ((char *) udp - (char *) data))
		return false;

	if (udp->dest != htons(67) && udp->source != htons(67))
		return false;

	if (dhcp->op != 1 && dhcp->op != 2)
		return false;

	if (!forward)
		return true;

	if (dhcp->op == 2)
		relayd_refresh_host(rif, pkt->eth.ether_shost, (void *) &pkt->iph.saddr);

	DPRINTF(2, "%s: handling DHCP %s\n", rif->ifname, (dhcp->op == 1 ? "request" : "response"));

	dhcp->flags |= htons(DHCP_FLAG_BROADCAST);

	udp->check = 0;
	sum = udplen + IPPROTO_UDP;
	sum = chksum(sum, (void *) &pkt->iph.saddr, 8);
	sum = chksum(sum, (void *) udp, udplen);
	if (sum == 0)
		sum = 0xffff;

	udp->check = htons(~sum);

	relayd_forward_bcast_packet(rif, data, len);

	return true;
}


