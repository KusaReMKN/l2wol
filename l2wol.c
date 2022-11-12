/*-
 * Copyright (c) 2022, KusaReMKN.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/bpf.h>

#include <netinet/in.h>

#include <err.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ETHERTYPE_WOL
#define ETHERTYPE_WOL 0x0842
#endif	/* !ETHERTYPE_WOL */

#define BPFFILE "/dev/bpf"

#define ETHLIKE(t) \
	((t) == IFT_ETHER || (t) == IFT_L2VLAN || (t) == IFT_BRIDGE)

#define MP_DESTCOUNT 16
struct magic_packet {
	struct ether_addr mp_allff;
	struct ether_addr mp_dest[MP_DESTCOUNT];
} __packed;

struct magic_frame {
	struct ether_header mf_header;
	struct magic_packet mf_payload;
} __packed;

static void usage(void);

int
main(int argc, char *argv[])
{
	int ch, brflag, fd, i;
	char ifname[IFNAMSIZ] = "";
	ssize_t written;
	struct ifaddrs *res, *ifa;
	struct ifreq ifr;
	struct sockaddr_dl *sdl;
	struct ether_addr etha, *dest;
	struct ether_header ethh;
	struct magic_frame mf;

	brflag = 0;
	while ((ch = getopt(argc, argv, "bi:")) != -1)
		switch (ch) {
		case 'b':
			brflag = 1;
			break;
		case 'i':
			if (strlen(optarg) >= sizeof(ifname))
				errx(1, "%s: interface name too long", optarg);
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

	if (getifaddrs(&res) == -1)
		err(1, "getifaddrs");
	for (ifa = res; ifa != NULL; ifa = ifa->ifa_next) {
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl == NULL || sdl->sdl_len == 0 || !ETHLIKE(sdl->sdl_type)
				|| sdl->sdl_alen != ETHER_ADDR_LEN)
			continue;
		if (ifname[0] == 0 && strlen(ifa->ifa_name) < sizeof(ifname))
			strncpy(ifname, ifa->ifa_name, sizeof(ifname));
		if (strcmp(ifname, ifa->ifa_name) == 0)
			break;
	}
	if (ifa == NULL)
		errx(1, "%s: interface does not exist or invalid interface",
				ifname);
	memcpy(&etha, LLADDR(sdl), sizeof(etha));
	freeifaddrs(res);

	fd = open(BPFFILE, O_WRONLY);
	if (fd == -1)
		err(1, "%s", BPFFILE);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		err(1, "BIOCSETIF");

	memset(&ethh, 0, sizeof(ethh));
	memset(&ethh.ether_dhost, 0xFF, sizeof(ethh.ether_dhost));
	memcpy(&ethh.ether_shost, &etha, sizeof(ethh.ether_shost));
	ethh.ether_type = htons(ETHERTYPE_WOL);

	for (; *argv != NULL; argv++) {
		dest = ether_aton(*argv);
		if (dest == NULL) {
			warnx("%s: invalid MAC address, skipping", *argv);
			break;
		}
		if (!brflag)
			memcpy(&ethh.ether_dhost, dest,
					sizeof(ethh.ether_dhost));

		memcpy(&mf.mf_header, &ethh, sizeof(mf.mf_header));
		memset(&mf.mf_payload.mp_allff, 0xFF,
				sizeof(mf.mf_payload.mp_allff));
		for (i = 0; i < MP_DESTCOUNT; i++)
			memcpy(mf.mf_payload.mp_dest + i, dest,
					sizeof(mf.mf_payload.mp_dest[0]));

		written = write(fd, &mf, sizeof(mf));
		if (written != sizeof(mf))
			err(1, "write: %s", BPFFILE);
	}

	close(fd);

	return 0;
}

static void
usage(void)
{
	(void)fprintf(stderr,
			"Usage: l2wol [-b] [-i interface] destination ...\n");
	exit(1);
}
