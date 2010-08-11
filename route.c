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

#include "relayd.h"

static struct uloop_fd rtnl_sock;
static unsigned int rtnl_seq, rtnl_dump_seq;

static void rtnl_route_set(struct relayd_host *host, bool add)
{
	static struct {
		struct nlmsghdr nl;
		struct rtmsg rt;
		struct {
			struct rtattr rta;
			uint8_t ipaddr[4];
		} __packed dst;
		struct {
			struct rtattr rta;
			int ifindex;
		} __packed dev;
	} __packed req;

	memset(&req, 0, sizeof(req));

	req.nl.nlmsg_len = sizeof(req);
	req.rt.rtm_family = AF_INET;
	req.rt.rtm_dst_len = 32;

	req.dst.rta.rta_type = RTA_DST;
	req.dst.rta.rta_len = sizeof(req.dst);
	memcpy(req.dst.ipaddr, host->ipaddr, sizeof(req.dst.ipaddr));

	req.dev.rta.rta_type = RTA_OIF;
	req.dev.rta.rta_len = sizeof(req.dev);
	req.dev.ifindex = host->rif->sll.sll_ifindex;

	req.nl.nlmsg_flags = NLM_F_REQUEST;
	req.rt.rtm_table = RT_TABLE_MAIN;
	if (add) {
		req.nl.nlmsg_type = RTM_NEWROUTE;
		req.nl.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

		req.rt.rtm_protocol = RTPROT_BOOT;
		req.rt.rtm_scope = RT_SCOPE_LINK;
		req.rt.rtm_type = RTN_UNICAST;
	} else {
		req.nl.nlmsg_type = RTM_DELROUTE;
		req.rt.rtm_scope = RT_SCOPE_NOWHERE;
	}

	send(rtnl_sock.fd, &req, sizeof(req), 0);
}

void relayd_add_route(struct relayd_host *host)
{
	rtnl_route_set(host, true);
}

void relayd_del_route(struct relayd_host *host)
{
	rtnl_route_set(host, false);
}

#ifndef NDA_RTA
#define NDA_RTA(r) \
    ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

static void rtnl_parse_newneigh(struct nlmsghdr *h)
{
	struct relayd_interface *rif = NULL;
	struct ndmsg *r = NLMSG_DATA(h);
	const uint8_t *lladdr = NULL;
	const uint8_t *ipaddr = NULL;
	struct rtattr *rta;
	int len;

	if (r->ndm_family != AF_INET)
		return;

	list_for_each_entry(rif, &interfaces, list) {
		if (rif->sll.sll_ifindex == r->ndm_ifindex)
			goto found_interface;
	}
	return;

found_interface:
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*r));
	for (rta = NDA_RTA(r); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
		switch(rta->rta_type) {
		case NDA_LLADDR:
			lladdr = RTA_DATA(rta);
			break;
		case NDA_DST:
			ipaddr = RTA_DATA(rta);
			break;
		default:
			break;
		}
	}

	if (!lladdr || !ipaddr || (r->ndm_state & (NUD_INCOMPLETE|NUD_FAILED)))
		return;

	if (!memcmp(lladdr, "\x00\x00\x00\x00\x00\x00", ETH_ALEN))
		return;

	DPRINTF(1, "%s: Found ARP cache entry for host "IP_FMT" ("MAC_FMT")\n",
		rif->ifname, IP_BUF(ipaddr), MAC_BUF(lladdr));
	relayd_refresh_host(rif, lladdr, ipaddr);
}

static void rtnl_parse_packet(void *data, int len)
{
	struct nlmsghdr *h;

	for (h = data; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
		if (h->nlmsg_type == NLMSG_DONE ||
		    h->nlmsg_type == NLMSG_ERROR)
			return;

		if (h->nlmsg_seq != rtnl_dump_seq)
			continue;

		if (h->nlmsg_type == RTM_NEWNEIGH)
			rtnl_parse_newneigh(h);
	}
}

static void rtnl_cb(struct uloop_fd *fd, unsigned int events)
{
	struct sockaddr_nl nladdr;
	static uint8_t buf[16384];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	do {
		int len;

		len = recvmsg(rtnl_sock.fd, &msg, 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;

			return;
		}

		if (!len)
			break;

		if (nladdr.nl_pid != 0)
			continue;

		rtnl_parse_packet(buf, len);
	} while (1);
}

int relayd_rtnl_init(void)
{
	struct sockaddr_nl snl_local;
	static struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req = {
		.nlh = {
			.nlmsg_len = sizeof(req),
			.nlmsg_type = RTM_GETNEIGH,
			.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST,
			.nlmsg_pid = 0,
		},
		.g.rtgen_family = AF_INET,
	};

	rtnl_sock.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rtnl_sock.fd < 0) {
		perror("socket(AF_NETLINK)");
		return -1;
	}

	snl_local.nl_family = AF_NETLINK;

	if (bind(rtnl_sock.fd, (struct sockaddr *) &snl_local, sizeof(struct sockaddr_nl)) < 0) {
		perror("bind");
		close(rtnl_sock.fd);
		return -1;
	}

	rtnl_sock.cb = rtnl_cb;
	uloop_fd_add(&rtnl_sock, ULOOP_READ | ULOOP_EDGE_TRIGGER);

	rtnl_seq = time(NULL);
	rtnl_dump_seq = rtnl_seq;
	req.nlh.nlmsg_seq = rtnl_seq;
	send(rtnl_sock.fd, &req, sizeof(req), 0);

	return 0;
}

void relayd_rtnl_done(void)
{
	uloop_fd_delete(&rtnl_sock);
	close(rtnl_sock.fd);
}
