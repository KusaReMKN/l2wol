/*-
 * SPDX short identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 KusaReMKN.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#if defined(__NetBSD__)
#include <net/if_ether.h>
#elif defined(__OpenBSD__)
#include <net/ethertypes.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#else /* !__NetBSD__ && !__OpenBSD__ */
#include <net/ethernet.h>
#endif /* __NetBSD__, __OpenBSD__ */
#ifdef __linux__
#include <linux/if_packet.h>
#include <netinet/ether.h>
#else /* !__linux__ */
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/bpf.h>
#endif /* __linux__ */

#include <arpa/inet.h>

#include <err.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __linux__
#define BPFFILE "/dev/bpf"
#endif /* !__linux__ */

#ifndef ETHERTYPE_WOL
#define ETHERTYPE_WOL 0x0842
#endif /* !ETHERTYPE_WOL */

/* Wake-on-LAN Magic Packet without Password field */
#define MP_COUNT 16
struct magic_packet {
	struct ether_addr mp_sync;		/* Synchronization Stream */
	struct ether_addr mp_target[MP_COUNT];	/* Target MAC address */
} __attribute__((__packed__));

/* Ethernet Type II Frame for Wake-on-LAN Magic Packet */
struct magic_frame {
	struct ether_header mf_header;		/* MAC Header */
	struct magic_packet mf_payload;		/* Magic Packet */
} __attribute__((__packed__));

static void usage(void);
static void get_ethaddr(char *, size_t, struct ether_addr *);
static int open_interface(const char *);

int
main(int argc, char *argv[])
{
	int brdflag, ch, fd, i;
	ssize_t written;
	char ifname[IFNAMSIZ] = "";
	struct ether_addr *dest, ethaddr;
	struct ether_header ethhead;
	struct magic_frame mf;

	brdflag = 0;
	while ((ch = getopt(argc, argv, "bi:")) != -1)
		switch (ch) {
		case 'b':
			brdflag = 1;
			break;
		case 'i':
			if (strlen(optarg) >= sizeof(ifname))
				err(1, "%s: interface name too long", optarg);
			strncpy(ifname, optarg, sizeof(ifname));
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	get_ethaddr(ifname, sizeof(ifname), &ethaddr);
	fd = open_interface(ifname);

	memset(&ethhead, 0, sizeof(ethhead));
	memset(&ethhead.ether_dhost, 0xFF, sizeof(ethhead.ether_dhost));
	memcpy(&ethhead.ether_shost, &ethaddr, sizeof(ethhead.ether_dhost));
	ethhead.ether_type = htons(ETHERTYPE_WOL);

	for (; *argv != NULL; argv++) {
		dest = ether_aton(*argv);
		if (dest == NULL) {
			warnx("%s: invalid MAC address, skipping", *argv);
			continue;
		}
		if (!brdflag)
			memcpy(&ethhead.ether_dhost, dest,
					sizeof(ethhead.ether_dhost));

		memcpy(&mf.mf_header, &ethhead, sizeof(mf.mf_header));
		memset(&mf.mf_payload.mp_sync, 0xFF,
				sizeof(mf.mf_payload.mp_sync));
		for (i = 0; i < MP_COUNT; i++)
			memcpy(mf.mf_payload.mp_target + i, dest,
					sizeof(mf.mf_payload.mp_target[0]));
		written = write(fd, &mf, sizeof(mf));
		if (written != sizeof(mf))
			err(1, "write");
	}

	close(fd);

	return 0;
}

static void
get_ethaddr(char *ifname, size_t ifnamsiz, struct ether_addr *ethaddr)
{
	struct ifaddrs *ifa, *res;
#ifdef __linux__
	struct sockaddr_ll *sll;
#else /* !__linux__ */
	struct sockaddr_dl *sdl;
#endif /* __linux__ */

	if (getifaddrs(&res) == -1)
		err(1, "getifaddrs");
	for (ifa = res; ifa != NULL; ifa = ifa->ifa_next) {
#ifdef __linux__
		if (ifa->ifa_addr == NULL
				|| ifa->ifa_addr->sa_family != AF_PACKET)
			continue;
		sll = (struct sockaddr_ll *)ifa->ifa_addr;
		if (sll->sll_hatype != ARPHRD_ETHER
				|| sll->sll_halen != ETHER_ADDR_LEN)
			continue;
#else /* !__linux__ */
		if (ifa->ifa_addr == NULL
				|| ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_type != IFT_ETHER
				|| sdl->sdl_alen != ETHER_ADDR_LEN)
			continue;
#endif /* __linux__ */
		if (ifname[0] == '\0' && strlen(ifa->ifa_name) < ifnamsiz)
			strncpy(ifname, ifa->ifa_name, ifnamsiz);
		if (strcmp(ifname, ifa->ifa_name) == 0)
			break;
	}
	if (ifa == NULL)
		errx(1, "%s: interface does not exist or is invalid", ifname);
#ifdef __linux__
	memcpy(ethaddr, sll->sll_addr, sizeof(*ethaddr));
#else /* !__linux__ */
	memcpy(ethaddr, LLADDR(sdl), sizeof(*ethaddr));
#endif /* __linux__ */
	freeifaddrs(res);
}

static int
open_interface(const char *ifname)
{
	int fd;
	struct ifreq ifr;
#ifdef __linux__
	struct sockaddr_ll sll;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_WOL));
	if (fd == -1)
		err(1, "AF_PACKET");
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
		err(1, "SIOCGIFINDEX");
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETHERTYPE_WOL);
	sll.sll_ifindex = ifr.ifr_ifindex;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
		err(1, "bind");
#else /* !__linux__ */

	fd = open(BPFFILE, O_WRONLY);
	if (fd == -1)
		err(1, "%s", BPFFILE);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		err(1, "BIOCSETIF");
#endif /* __linux__ */

	return fd;
}

static void
usage(void)
{
	(void)fprintf(stderr,
			"usage: l2wol [-b] [-i interface] destination ...\n");
	exit(1);
}
