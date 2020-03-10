/*
 * probedhcp.c
 *
 * Simple program which sends IPv4 UDP packets using raw sockets.  Varies
 * TTL to in the style of traceroute(1) but doesn't capture ICMP replies.
 * Unlike traceroute, doesn't vary the source and destination ports.
 *
 * Default source port is 68 and destination port is 67.  These are the
 * defaults for DHCP packets and this program can be used to test DHCP relays
 * and see how far unicast (not broadcast) DHCP packets get from a client to
 * a DHCP server (hence the name of this program.)  Handy for finding if your
 * routers are snooping DHCP and silently discarding packets.
 *
 * The most useful way of running this program is with a tcpdump(8) running
 * alongside to capture ICMP responses to each probe.
 *
 * Note there is no payload in the packet.  If your DHCP server can't cope
 * cope with this, you need a better DHCP server.  Also since we don't aim
 * to deliver any actual data, we don't bother computing the packet checksum
 * in the UDP header.  The kernel will fill in the source IP address of the
 * packet and compute the packet header checksum for us.
 *
 * Copyright (C) 2020 Aled Morris
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define SRC_PORT 68
#define DST_PORT 67
#define MAX_TTL  32

int
main(int argc, char **argv)
{
	char *progname = argv[0];
	int sport = SRC_PORT;
	int dport = DST_PORT;

	int ch;
	while ((ch = getopt(argc, argv, "s:d:")) != -1) {
		switch (ch) {
		case 's':
			sport = atoi(optarg);
			break;
		case 'd':
			dport = atoi(optarg);
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1 || sport < 1 || dport < 1) {
		fprintf(stderr, "usage: %s [-s src_port] [-d dst_port] host\n",
			progname);
		exit(1);
	}

	struct addrinfo hints, *res;
	bzero(&hints, sizeof hints);
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_RAW;
	int error;
	if ((error = getaddrinfo(argv[0], NULL, &hints, &res))) {
		fprintf(stderr, "%s: %s", argv[0], gai_strerror(error));
		exit(1);
	}
	struct sockaddr_in to;
	bcopy(res->ai_addr, &to, res->ai_addrlen);
	freeaddrinfo(res);

	int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0) {
		perror("socket");
		exit(1);
	}
	int on = 1;
	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof on) == -1) {
		perror("setsockopt");
		exit(1);
	}

	u_int8_t pkt[sizeof (struct ip) + sizeof (struct udphdr)];
	bzero(pkt, sizeof pkt);

        struct ip *ip_hdr = (struct ip *)pkt;
	ip_hdr->ip_v     = 4;
	ip_hdr->ip_hl    = sizeof (struct ip) >> 2;
	ip_hdr->ip_len   = sizeof pkt;
	ip_hdr->ip_id    = getpid();
	ip_hdr->ip_p     = IPPROTO_UDP;
	ip_hdr->ip_dst   = to.sin_addr;

        struct udphdr *udp_hdr = (struct udphdr *)(pkt + sizeof (struct ip));
	udp_hdr->source = htons(sport);
	udp_hdr->dest   = htons(dport);
	udp_hdr->len    = htons(sizeof (struct udphdr));

	int ttl;
	for (ttl = 1; ttl < MAX_TTL; ttl++) {
		ip_hdr->ip_ttl = ttl;
		printf("sending ttl %d\n", ttl);
		if (sendto(s, pkt, sizeof pkt, 0, (struct sockaddr *)&to, sizeof to) < 0) {
			perror("sendto");
			exit(1);
		}
		sleep(1);
	}
}

//end
