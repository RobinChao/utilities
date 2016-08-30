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
 *
 * See netdevice(7) for
 * - SIOCGIFADDR
 * - SIOCGIFBRDADDR
 * - SIOCGIFCONF (here)
 * - SIOCGIFDSTADDR
 * - SIOCGIFFLAGS
 * - SIOCGIFHWADDR (here)
 * - SIOCGIFINDEX
 * - SIOCGIFMAP
 * - SIOCGIFMETRIC
 * - SIOCGIFMTU
 * - SIOCGIFNAME
 * - SIOCGIFNETMASK
 * - SIOCGIFPFLAGS
 * - SIOCGIFTXQLEN
 */
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

/* legacy mode decls */
extern int getopt(int argc, char * const argv[], const char *optstring);
extern char *optarg;
extern int optind, opterr, optopt;

/* bool type is not a default feature in C */
typedef enum { false = 0, true = 1 } bool;

static struct {
	int mode;
	bool ifname_set;
	char ifname[IFNAMSIZ+1];
	bool show_ip;
	bool show_mac;
	bool flags_set;
	short flags;
	bool verbose;
} global = {};

int run_ioctl(int opcode, void *arg)
{
	int rc, sock = socket(AF_INET, SOCK_DGRAM, 0);

	if (sock < 0) {
		if (global.verbose) perror("socket");
		return sock;
	}

	rc = ioctl(sock, opcode, arg);
	if (rc) {
		// if (global.verbose) perror("ioctl");
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
		if (global.verbose) perror("query_response_size");
		return rc;
	}

	return ifc.ifc_len;
}

int query_if_hwaddr(struct ifreq *req)
{
	int rc = run_ioctl(SIOCGIFHWADDR, req);

	if (rc) {
		if (global.verbose) perror("query_if_hwaddr:ioctl");
		return rc;
	}

	return 0;
}

int query_ip_addr(struct ifreq *req)
{
	int rc;

	req->ifr_addr.sa_family = AF_INET;
	rc = run_ioctl(SIOCGIFADDR, req);

	if (rc) {
		if (global.verbose) perror("query_ip_addr:ioctl");
		return rc;
	}

	return 0;
}

int query_if_flags(struct ifreq *req)
{
	int rc = run_ioctl(SIOCGIFHWADDR, req);

	if (rc) {
		if (global.verbose) perror("query_if_flags:ioctl");
		return rc;
	}

	return 0;
}

enum addr_fmt {
	ADDR_FMT_LONG,
	ADDR_FMT_SHORT,
};

static const char iff_flag_delimiter[] = ",";
#define _STR(x) ""#x
#define IFF_FLAG2STR(flag, value, string, descr)			\
	do {								\
		if ((value) & (IFF_##flag)) {				\
			if ((string)[0])				\
				strcat((string), iff_flag_delimiter);	\
			strcat((string), _STR(flag));			\
		}							\
	} while (0)

static inline char *if_flags(short flags, enum addr_fmt fmt)
{
	static char sflags[128];

	memset(sflags, 0, sizeof(sflags));
	/* sprintf(sflags, "0x%0*x", (int)sizeof(flags) * 2, flags); */
	IFF_FLAG2STR(UP, flags, sflags, "Interface is up");
	IFF_FLAG2STR(BROADCAST, flags, sflags, "Broadcast address valid");
	IFF_FLAG2STR(DEBUG, flags, sflags, "Turn on debugging");
	IFF_FLAG2STR(LOOPBACK, flags, sflags, "Is a loopback net");
	IFF_FLAG2STR(POINTOPOINT, flags, sflags, "Interface is point-to-point link");
	IFF_FLAG2STR(NOTRAILERS, flags, sflags, "Avoid use of trailers");
	IFF_FLAG2STR(RUNNING, flags, sflags, "Resources allocated");
	IFF_FLAG2STR(NOARP, flags, sflags, "No address resolution protocol");
	IFF_FLAG2STR(PROMISC, flags, sflags, "Receive all packets");
	IFF_FLAG2STR(ALLMULTI, flags, sflags, "Receive all multicast packets");
	IFF_FLAG2STR(MASTER, flags, sflags, "Master of a load balancer");
	IFF_FLAG2STR(SLAVE, flags, sflags, "Slave of a load balancer");
	IFF_FLAG2STR(MULTICAST, flags, sflags, "Supports multicast");
	IFF_FLAG2STR(PORTSEL, flags, sflags, "Can set media type");
	IFF_FLAG2STR(AUTOMEDIA, flags, sflags, "Auto media select active");
	IFF_FLAG2STR(DYNAMIC, flags, sflags, "Dialup device with changing addresses");

	return sflags;
}

static const char *_families[] = {
	[AF_UNSPEC] = "UNSPEC",
	[AF_LOCAL] = "LOCAL", /* == [AF_UNIX] == [AF_FILE] */
	[AF_INET] = "INET",
	[AF_AX25] = "AX25",
	[AF_IPX] = "IPX",
	[AF_APPLETALK] = "APPLETALK",
	[AF_NETROM] = "NETROM",
	[AF_BRIDGE] = "BRIDGE",
	[AF_ATMPVC] = "ATMPVC",
	[AF_X25] = "X25",
	[AF_INET6] = "INET6",
	[AF_ROSE] = "ROSE",
	[AF_DECnet] = "DECnet",
	[AF_NETBEUI] = "NETBEUI",
	[AF_SECURITY] = "SECURITY",
	[AF_KEY] = "KEY",
	[AF_NETLINK] = "NETLINK",
	[AF_ROUTE] = "ROUTE",
	[AF_PACKET] = "PACKET",
	[AF_ASH] = "ASH",
	[AF_ECONET] = "ECONET",
	[AF_ATMSVC] = "ATMSVC",
	[AF_RDS] = "RDS",
	[AF_SNA] = "SNA",
	[AF_IRDA] = "IRDA",
	[AF_PPPOX] = "PPPOX",
	[AF_WANPIPE] = "WANPIPE",
	[AF_LLC] = "LLC",
	[AF_IB] = "IB",
	[AF_MPLS] = "MPLS",
	[AF_CAN] = "CAN",
	[AF_TIPC] = "TIPC",
	[AF_BLUETOOTH] = "BLUETOOTH",
	[AF_IUCV] = "IUCV",
	[AF_RXRPC] = "RXRPC",
	[AF_ISDN] = "ISDN",
	[AF_PHONET] = "PHONET",
	[AF_IEEE802154] = "IEEE802154",
	[AF_CAIF] = "CAIF",
	[AF_ALG] = "ALG",
	[AF_NFC] = "NFC",
	[AF_VSOCK] = "VSOCK",
};

static inline const char *af_name(int af)
{
	if (af >= 0 && af < AF_MAX)
		return _families[af];
	return NULL;
}

static inline char *add_af_name(char *s, int af, enum addr_fmt fmt)
{
	static int af_name_len_max;

	if (!af_name_len_max) {
		int i;

		for (i = 0; i < AF_MAX; i++) {
			int l = strlen(af_name(i));

			if (l > af_name_len_max)
				af_name_len_max = l;
		}
		af_name_len_max++; /* add a space */
	}

	switch (fmt) {
	case ADDR_FMT_LONG:
		sprintf(s, "%-*.*s", af_name_len_max, af_name_len_max, af_name(af));
		break;
	case ADDR_FMT_SHORT:
		strcpy(s, af_name(af));
		strcat(s, " ");
		break;
	}
	s += strlen(s);
	return s;
}

#define min(x,y) (((x) > (y)) ? (y) : (x))

static inline void rpad4fmt(char *s, int s_size, int pad_size, enum addr_fmt fmt)
{
	while (fmt == ADDR_FMT_LONG && strlen(s) < min(s_size, pad_size))
		strncat(s, " ", s_size);
}

static inline int fetch_address(const struct sockaddr *sa, char *s, int size)
{
	int inf_size = -1;

	switch (sa->sa_family) {
	case AF_INET:  inf_size = sizeof(struct sockaddr_in); break;
	case AF_INET6: inf_size = sizeof(struct sockaddr_in6); break;
	}

	return getnameinfo(sa, inf_size, s, size, NULL, 0, NI_NUMERICHOST);
}

static inline char *ip_addr(const struct sockaddr *sa, enum addr_fmt fmt)
{
	const int af = sa->sa_family;
	static char addr[64];
	char *fmx, *p;
	int i, rc, pad_size;

	addr[0] = '\0';
	p = (fmt == ADDR_FMT_LONG) ? add_af_name(addr, af, fmt) : addr;

	switch (af) {
	case AF_INET:  pad_size = strlen(addr) + 15; break;
	case AF_INET6: pad_size = strlen(addr) + 40; break;
	default: pad_size = 0; break;
	}

	switch (af) {
	case AF_INET:
	case AF_INET6:
		rc = fetch_address(sa, p, min(sizeof(addr) - strlen(addr), NI_MAXHOST));
		if (rc) {
			strcat(addr, "<error:");
			strncat(addr, gai_strerror(rc), sizeof(addr));
			strncat(addr, ">", sizeof(addr));
			return addr;
		}
		rpad4fmt(addr, sizeof(addr), pad_size, fmt);
		break;
		/*
	case AF_INET:
		switch (fmt) {
		case ADDR_FMT_LONG:	fmx = "%-15.15s"; break;
		case ADDR_FMT_SHORT:	fmx = "%s"; break;
		}
		switch (global.mode) {
		case 1: p = addr; break;
		case 2:
		case 3:
			break;
		default: assert(false); break;
		}
		sprintf(p, fmx, inet_ntoa(*(struct in_addr *)&sa->sa_data[2]));
		break;
		*/
	case AF_PACKET: /* no real IP here, of course */
		strcat(p, "-");
		break;
	default:
		sprintf(p, "<%d/", af);
		for (i = 0, p = addr + strlen(addr); i < sizeof(sa->sa_data); i++)
			sprintf(p + i * 3, "%02x%s", (uint8_t) sa->sa_data[i],
				(i < sizeof(sa->sa_data) - 1) ? ":" : ">");
		break;
	}
	return addr;
}

static inline char *hw_addr(const struct sockaddr *sa, enum addr_fmt fmt)
{
	const int af = sa->sa_family;
	uint8_t *data = (uint8_t *) &sa->sa_data[0];
	const size_t data_size = sizeof(sa->sa_data);
	static char mac[64]; /* ETHER aa:bb:cc:dd:ee:ff */
	char *p, *fmx;
	int i;

	switch (af) {
	case ARPHRD_LOOPBACK:
		switch (fmt) {
		case ADDR_FMT_LONG:	fmx = "LOOPBACK -"; break;
		case ADDR_FMT_SHORT:	fmx = "-"; break;
		}
		strcpy(mac, fmx);
		break;
	case ARPHRD_ETHER:
		switch (fmt) {
		case ADDR_FMT_LONG:	fmx = "ETHER %02x:%02x:%02x:%02x:%02x:%02x"; break;
		case ADDR_FMT_SHORT:	fmx = "%02x:%02x:%02x:%02x:%02x:%02x"; break;
		}
		sprintf(mac, fmx, data[0], data[1], data[2], data[3], data[4], data[5]);
		break;
	default:
		switch (fmt) {
		case ADDR_FMT_LONG:
			sprintf(mac, "<%d> <", af);
			break;
		case ADDR_FMT_SHORT:
			strcpy(mac, "<");
			break;
		}
		for (i = 0, p = mac + strlen(mac); i < data_size; i++)
			sprintf(p + i * 3, "%02x%s", data[i],
				(i < data_size - 1) ? ":" : ">");
		break;
	}

	return mac;
}

static inline void add_ip_addr(void *ifx, const char *errmsg, enum addr_fmt fmt)
{
	struct sockaddr *sa;
	struct ifreq *ifr = ifx;
	struct ifaddrs *ifa = ifx;

	switch (global.mode) {
	case 1: /* already fetched */ sa = &ifr->ifr_addr; break;
	case 2: sa = query_ip_addr(ifr) ? NULL : &ifr->ifr_addr; break;
	case 3: /* already fetched */ sa = ifa->ifa_addr; break;
	}

	fputs(sa ? ip_addr(sa, fmt) : errmsg, stdout);
}

static inline void add_hw_addr(struct ifreq *ifr, const char *errmsg, enum addr_fmt fmt)
{
	fputs(query_if_hwaddr(ifr) ? errmsg : hw_addr(&ifr->ifr_addr, fmt), stdout);
}

static inline void add_flags(void *ifx, const char *errmsg, enum addr_fmt fmt)
{
	struct ifreq *ifr = ifx;
	struct ifaddrs *ifa = ifx;
	int flags = -1;

	switch (global.mode) {
	case 1:
	case 2: flags = query_if_flags(ifr) ? -1 : ifr->ifr_flags; break;
	case 3: /* already fetched */ flags = ifa->ifa_flags; break;
	}

	fputs((flags == -1) ? errmsg : if_flags(flags, fmt), stdout);
}

static inline void add_if_name(void *ifx, enum addr_fmt fmt)
{
	struct ifreq *ifr = ifx;
	struct ifaddrs *ifa = ifx;
	char *name;

	switch (global.mode) {
	case 1:
	case 2: name = ifr->ifr_name; break;
	case 3: name = ifa->ifa_name; break;
	}

	switch (fmt) {
	case ADDR_FMT_LONG:
		printf("%-*.*s", IFNAMSIZ, IFNAMSIZ, name);
		break;
	case ADDR_FMT_SHORT:
		fputs(name, stdout);
		break;
	}
}

static void print_interface(struct ifreq *ifr)
{
	if (global.ifname_set) {
		if (strncmp(ifr->ifr_name, global.ifname, IFNAMSIZ))
			return;
		if (global.show_ip || !global.show_mac) {
			add_ip_addr(ifr, NULL, ADDR_FMT_SHORT);
			fputs(global.show_ip ? "" : "\t", stdout);
		}
		if (global.show_mac || !global.show_ip)
			add_hw_addr(ifr, "<no-hw-addr>", ADDR_FMT_SHORT);
		putchar('\n');
		return;
	}

	add_if_name(ifr, ADDR_FMT_LONG);
	printf(" : ");
	add_ip_addr(ifr, "<error> -", ADDR_FMT_LONG);
	printf(" : ");
	add_hw_addr(ifr, "<error> <no-hw-addr>", ADDR_FMT_LONG);

	if (global.flags_set) {
		printf(" : ");
		add_flags(ifr, "<error-no-flags>", ADDR_FMT_LONG);
	}

	putchar('\n');
}

static void print_address(struct ifaddrs *ifa)
{
	if (global.ifname_set) {
		if (strncmp(ifa->ifa_name, global.ifname, IFNAMSIZ))
			return;
	} else {
		add_if_name(ifa, ADDR_FMT_LONG);
		printf(" : ");
	}
	if (ifa->ifa_addr == NULL) {
		printf("<no-address>\n");
		return;
	}
	add_ip_addr(ifa, "<error> -", ADDR_FMT_LONG);
	if (global.flags_set) {
		printf(" : ");
		add_flags(ifa, "<error-no-flags>", ADDR_FMT_LONG);
	}
	putchar('\n');
	return;
}

static void __dispose_req(struct ifreq **req)
{
	if (req && *req) {
		free(*req);
		*req = 0;
	}
}

static int __1__query_if_list(void)
{
	struct ifreq *req __attribute__((cleanup(__dispose_req))) = NULL;
	struct ifconf ifc = {};
	int rc, i, j, size = query_response_size();

	if (size <= 0) return -1;

	req = calloc(size, 1);
	if (!req) {
		if (global.verbose) perror("query_if_list:cmalloc");
		return -1;
	}

	ifc.ifc_len = size;
	ifc.ifc_req = req;

	rc = run_ioctl(SIOCGIFCONF, &ifc);
	if (rc) {
		if (global.verbose) perror("query_if_list:ioctl");
		return rc;
	}

	for (i = 0; i < ifc.ifc_len / sizeof(struct ifreq); i++) {
		struct ifreq *ifr = &ifc.ifc_req[i];

		if (global.ifname_set) {
			if (strncmp(ifr->ifr_name, global.ifname, IFNAMSIZ))
				continue;
		} else
			printf("%2d: ", i + 1);
		print_interface(ifr);
	}

	return 0;
}

static void __dispose_if_list_2(struct if_nameindex **if_list)
{
	if (if_list && *if_list) {
		if_freenameindex(*if_list);
		*if_list = 0;
	}
}

static int __2__query_if_list(void)
{
	struct if_nameindex *i;
	struct if_nameindex *if_list
		__attribute__((cleanup(__dispose_if_list_2)))
		= if_nameindex();

	if (!if_list) {
		if (global.verbose) perror("if_nameindex");
		return -1;
	}
	for (i = if_list; ! (i->if_index == 0 && i->if_name == NULL); i++) {
		struct ifreq ifr;

		// printf("%u: %s\n", i->if_index, i->if_name);
		strncpy(ifr.ifr_name, i->if_name, sizeof(ifr.ifr_name));
		print_interface(&ifr);
	}

	return 0;
}

static void __dispose_if_list_3(struct ifaddrs **if_list)
{
	if (if_list && *if_list) {
		freeifaddrs(*if_list);
		*if_list = 0;
	}
}

static int __3__query_if_list(void)
{
	struct ifaddrs *ifa;
	struct ifaddrs *if_list __attribute__((cleanup(__dispose_if_list_3))) = NULL;

	if (getifaddrs(&if_list) == -1) {
		if (global.verbose) perror("getifaddrs");
		return -1;
	}

	for (ifa = if_list; ifa != NULL; ifa = ifa->ifa_next) {
//		if (!ifa->ifa_addr)
//			continue;
		print_address(ifa);
	}
}

int query_if_list(void)
{
	switch (global.mode) {
	case 1: return __1__query_if_list();
	case 2: return __2__query_if_list();
	case 3: return __3__query_if_list();
	}
}

static char HELP[] = "%s [-f] [-i <interface> [-a | -m]]\n\n"
	"Options:\n"
	" -h -- this help\n"
	" -1, -2, -3 -- use different query schemes:\n"
	"	SIOCGIFCONF, if_nameindex, getifaddrs\n"
	" -i <interface> -- set <interface> name to query for\n"
	" -a -- list IP addresses\n"
	" -m -- list MAC addresses (you may want to use 'sort -u') here\n"
	" -f -- add flags to the output\n"
	" -v -- verbose\n"
	"\n";

static int parse_args(int argc, char * const argv[])
{
	const static char optspec[] = "hvi:amf123";

	global.mode = 1; /* default */

	while (true) {
		int opt = getopt(argc, argv, optspec);

		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			printf(HELP, argv[0]);
			exit(EXIT_SUCCESS);

		case '1': global.mode = 1; break;
		case '2': global.mode = 2; break;
		case '3': global.mode = 3; break;
		case '4': global.mode = 4; break;
		case '5': global.mode = 5; break;
		case '6': global.mode = 6; break;
		case '7': global.mode = 7; break;
		case '8': global.mode = 8; break;
		case '9': global.mode = 9; break;

		case 'i':
			global.ifname_set = true;
			strncpy(global.ifname, optarg, IFNAMSIZ);
			continue;
		case 'a':
			global.show_ip = true;
			continue;
		case 'm':
			global.show_mac = true;
			continue;
		case 'f':
			global.flags_set = true;
			continue;
		case 'v':
			global.verbose = true;
			continue;
		default:
			return -1;
		}
	}

	/* argv[optind] may be parsed here */

	if (optind < argc) {
		fprintf(stderr, "%s: trailing extra args\n", argv[0]);
		return -1;
	}

	if ((global.show_ip || global.show_mac) && !global.ifname_set) {
		fprintf(stderr, "%s: -a and -m require -i <interface>.\n", argv[0]);
		return -1;
	}

	if (global.show_ip && global.show_mac) {
		/* just turn'em off */
		global.show_ip = false;
		global.show_mac = false;
		/*
		fprintf(stderr, "%s: -a and -m are mutually exclusive.\n", argv[0]);
		return -1;
		*/
	}

	return 0;
}

int main(int argc, char * const argv[])
{
	if (parse_args(argc, argv))
		return EXIT_FAILURE;

 	if (query_if_list())
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
