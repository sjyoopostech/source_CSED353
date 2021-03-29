#include <stdio.h>
#include <pcap.h>
#include <time.h>

#define ETHERTYPE_IP 0x0800

// Ethernet header
struct ethernet_header {
	u_char ether_dhost[6];	// Destination Address
	u_char ether_shost[6];	// Source Address
	u_short ether_type;	// Type
};

// IP header
struct ip_header {
	u_char ip_vhl;		// Version & HL
	u_char ip_tos;		// Type of Service
	u_short ip_len;		// Total Length
	u_short ip_id;		// identification
	u_short ip_off;		// Flags & Fragment offset
	u_char ip_ttl;		// TTL
	u_char ip_p;		// Protocol
	u_short ip_sum;		// Checksum
	u_char ip_src[4];	// Source Address
	u_char ip_dst[4];	// Destination Address
};

// TCP header
struct tcp_header {
	u_short tcp_src;	// Source Port
	u_short tcp_dst;	// Destination Port
	u_int tcp_seq;		// Sequence number
	u_int tcp_ack;		// Acknowledgement number
	u_short tcp_lenflag;	// Length & Flag
	u_short tcp_window;	// Window Size
	u_short tcp_sum;	// Checksum
	u_short tcp_uptr;	// Urgent Pointer
};

// UDP header
struct udp_header {
	u_short udp_src;	// Source Port
	u_short udp_dst;	// Destination Port
	u_short udp_len;	// Length
	u_short udp_sum;	// Checksum
};

// ICMP header
struct icmp_header {
	u_char icmp_type;	// Type
	u_char icmp_code;	// Code
	u_short icmp_sum;	// Checksum
};


clock_t start = NULL;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	int i;    

	struct ethernet_header *ethernet;
	struct ip_header *ip;
	struct tcp_header *tcp;
	struct udp_header *udp;
	struct icmp_header *icmp;

	int size_ethernet;
	int size_ip;

	ethernet = (struct ethernet_header*)(packet);
	size_ethernet = 14;
	if (ethernet->ether_type != 0x0008) return;	// Not IP

	ip = (struct ip_header*)(packet+size_ethernet);
	size_ip = ((ip->ip_vhl) & 0x0f)*4;
	if (size_ip < 20) return;			// Invalid IP Packet

	if (ip->ip_p == 1) {				// ICMP Packet
		icmp = (struct icmp_header*)(packet+size_ethernet+size_ip);
		printf("\033[41m");
	}
	else if (ip->ip_p == 6) {			// TCP Packet
		tcp = (struct tcp_header*)(packet+size_ethernet+size_ip);
		printf("\033[44m");
	}
	else if (ip->ip_p == 17) {			// UDP Packet
		udp = (struct udp_header*)(packet+size_ethernet+size_ip);
		printf("\033[45m");
	}
	else return;					// Neither

	// Time Part
	if (start == NULL) start = times();
	printf("%.4f: ",(double)(times()-start)/100);

	// Packet Ethernet Part
	printf("[");
	for (i = 0; i < 6; i++) {
		if (i > 0) printf(":");
		printf("%02x", (ethernet->ether_shost)[i]);
	}
	printf("->");
	for (i = 0; i < 6; i++) {
		if (i > 0) printf(":");
		printf("%02x", (ethernet->ether_dhost)[i]);
	}
	printf("]");

	// Packet IP Part
	printf("(");
	for (i = 0; i < 4; i++) {
		if (i > 0) printf(".");
		printf("%u", (ip->ip_src)[i]);
	}
	printf("->");
	for (i = 0; i < 4; i++) {
		if (i > 0) printf(".");
		printf("%u", (ip->ip_dst)[i]);
	}    
	printf(")");

	// Packet TCP/UDP/ICMP Part
	if (ip->ip_p == 1) {                    // ICMP Packet
		printf(" ICMP");
		printf(" Type:%u, Code:%u", icmp->icmp_type, icmp->icmp_code);
	}
	else if (ip->ip_p == 6) {               // TCP Packet
		printf(" TCP");
		printf(" Src_port:%u, Dst_port:%u, Seq:%u, Ack:%u", tcp->tcp_src, tcp->tcp_dst, tcp->tcp_seq, tcp->tcp_ack);
	}
	else if (ip->ip_p == 17) {              // UDP Packet
		printf(" UDP");
		printf(" Src_port:%u, Dst_port:%u", udp->udp_src, udp->udp_dst);
	}
	printf("\033[0m\n");
}


int main(void) {

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_if_t *interface_list;
	pcap_if_t *interface;
	int interface_num;

	char *dev;
	pcap_t *handle;

	int i = 0;

	// Finding & Selecting Interface
	if (pcap_findalldevs(&interface_list, errbuf) == -1) {
		printf("pcap_findalldevs error\n");
		return 1;
	}
	if (interface_list == NULL) {
		printf("Interface list error: %s\n", errbuf);
		return 1;
	}
	for (interface=interface_list; interface != NULL; interface=interface->next) {
		i++;
		printf("%d. %s", i, interface->name);
		if (interface->description == NULL) printf(" (No description available)");
		else printf(" (%s)", interface->description);
		printf("\n");
	}
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &interface_num);
	if (interface_num < 1 || interface_num > i) {
		printf("Interface number error\n");
		pcap_freealldevs(interface_list);
		return 1;
	}
	i=0;
	for (interface=interface_list; interface != NULL; interface=interface->next) {
		i++;
		if (i == interface_num) break;
	}
	dev = interface->name;
	printf("\nselected device %s is available\n\n", dev);

	// Packet Collecting
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		pcap_freealldevs(interface_list);
		return 1;
	}
	pcap_freealldevs(interface_list);
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle);

	return 0;
}
