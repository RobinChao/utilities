/* Copyright Yadro (C) 2016
 * Author: ed@ngslab.ru
 *
 * For those who have pissed off awking output of ip(8)...
 *
 * [root@opt-03 ~]# ./lsif 
 *  1: lo              : 127.0.0.1      : LOOPBACK -
 *  2: eno1            : 172.17.32.102  : ETHER 6c:ae:8b:2c:eb:18
 *  3: br-ctlplane     : 192.0.2.1      : ETHER 6c:ae:8b:2c:eb:19
 *  4: br-ctlplane     : 192.0.2.3      : ETHER 6c:ae:8b:2c:eb:19
 *  5: br-ctlplane     : 192.0.2.2      : ETHER 6c:ae:8b:2c:eb:19
 */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

int run_ioctl(int opcode, void *arg)
{
	int rc, sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {
		perror("socket");
		return sock;
	}

	rc = ioctl(sock, opcode, arg);
	if (rc) {
		// perror("ioctl");
		close(sock);
		return rc;
	}

	close(sock);
	return 0;
}

int query_response_size(void)
{
	struct ifconf ifc = {};
	int rc = run_ioctl(SIOCGIFCONF, &ifc);

	if (rc) {
		perror("query_response_size");
		return rc;
	}

	return ifc.ifc_len;
}

int query_if_hwaddr(struct ifreq *req)
{
	int rc = run_ioctl(SIOCGIFHWADDR, req);

	if (rc) {
		perror("query_if_hwaddr:ioctl");
		return rc;
	}

	return 0;
}

static inline char *ipv4addr(const struct sockaddr *sa)
{
	static char addr[64], *p;
	int i;

	switch (sa->sa_family) {
	case AF_INET:
		// sprintf(addr, "INET %-15.15s", 
		sprintf(addr, "%-15.15s", 
			inet_ntoa(*(struct in_addr *)&sa->sa_data[2]));
		break;
	default:
		sprintf(addr, "<%d/", sa->sa_family);
		for (i = 0, p = addr + strlen(addr); i < sizeof(sa->sa_data); i++)
			sprintf(p + i * 3, "%02x%s", (uint8_t) sa->sa_data[i],
				(i < sizeof(sa->sa_data) - 1) ? ":" : ">");
		break;
	}
	return addr;
	// return inet_ntoa(*(struct in_addr *)&sa->sa_data[2]);
}

static inline char *hw_addr(const struct sockaddr *sa)
{
	static char *p, mac[64]; /* ETHER aa:bb:cc:dd:ee:ff */
	int i;

	switch (sa->sa_family) {
	case ARPHRD_LOOPBACK:
		sprintf(mac, "LOOPBACK -");
		break;
	case ARPHRD_ETHER:
		sprintf(mac, "ETHER %02x:%02x:%02x:%02x:%02x:%02x",
			(uint8_t) sa->sa_data[0], (uint8_t) sa->sa_data[1],
			(uint8_t) sa->sa_data[2], (uint8_t) sa->sa_data[3],
			(uint8_t) sa->sa_data[4], (uint8_t) sa->sa_data[5]);
		break;
	default:
		sprintf(mac, "<%d> <", sa->sa_family);
		for (i = 0, p = mac + strlen(mac); i < sizeof(sa->sa_data); i++)
			sprintf(p + i * 3, "%02x%s", (uint8_t) sa->sa_data[i],
				(i < sizeof(sa->sa_data) - 1) ? ":" : ">");
		break;
	}

	return mac;
}

int query_if_list(int size)
{
	struct ifreq *req = NULL;
	struct ifconf ifc = {};
	char ifnamefmt[16];
	int rc, i, j;

	if (size <= 0) return -1;

	req = calloc(size, 1);
	if (!req) {
		perror("query_if_list:cmalloc");
		return -1;
	}

	ifc.ifc_len = size;
	ifc.ifc_req = req;

	rc = run_ioctl(SIOCGIFCONF, &ifc);
	if (rc) {
		perror("query_if_list:ioctl");
		return rc;
	}

	sprintf(ifnamefmt, "%%-%d.%ds", IFNAMSIZ, IFNAMSIZ);
	for (i = 0; i < ifc.ifc_len / sizeof(struct ifreq); i++) {
		struct sockaddr mac;
		struct ifreq *ifr = &ifc.ifc_req[i];

		printf("%2d: ", i + 1);
		printf(ifnamefmt, ifr->ifr_name);
		printf(": %-20s", ipv4addr(&ifr->ifr_addr));

		if (query_if_hwaddr(ifr))
			printf("<no-hw-addr>");
		else {
			printf(": %s", hw_addr(&ifr->ifr_addr));
		}

		printf("\n");
	}

	return 0;
}

int main(int argc, const char **argv)
{
 	if (query_if_list(query_response_size()))
		return 1;

	return 0;
}
