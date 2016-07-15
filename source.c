#include <pcap.h>
#include <winsock2.h>
#include <string.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib")



typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;


/* IPv4 header */
typedef struct ip_header {
	u_char  ip_leng : 4;    // Version (4 bits) + 
	u_char  ip_version : 4; // Internet header length(4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP header*/
typedef struct tcp_header {
	u_short sport;					// Source port
	u_short dport;					// Destination port
	u_long sequence_number;			// sequence_number
	u_long Ac_number;				// Acknowledgement number
	u_char H_len : 4;				// Header Length
	u_char reserved_area : 6;		// reserved Area
	unsigned char fin : 1;			// FIN Flags
	unsigned char syn : 1;			// SYN Flags
	unsigned char rst : 1;			// RST Flags
	unsigned char psh : 1;			// PSH Flags
	unsigned char ack : 1;			// ACK Flags
	unsigned char urg : 1;			// URG Flags
	unsigned short window;			// Window size
	unsigned short checksum;		// Checksum
	unsigned short urgent_pointer;  // Urgent pointer
}tcp_header;

typedef struct ether_addr
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}ether_addr;

typedef struct ether_header
{
	struct  ether_addr ether_dhost;//ethernet destination MAC
	struct  ether_addr ether_shost;//ethernet source MAC
	unsigned short ether_type;	   //ethernet Type
}ether_header;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and tcp";
	struct bpf_program fcode;

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open(d->name,
		65536,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

/* ������ ��� ��Ŷ�� ���� winpcap�� ȣ�� �ݹ� ��� */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	ether_header *eh;
	ip_header *ih;
	tcp_header *th;
	u_int ip_len;
	u_short sport, dport;

	eh = (ether_header *)(pkt_data);

	ih = (ip_header *)(pkt_data +
		14); // ip����� �����͸� ethernet ����� ������ 14����Ʈ��ŭ �Ű��ش�.

	ip_len = (ih->ip_leng) * 4;//*4�� ����Ʈ ������ �ٲپ� �־�� �Ѵ�. 

	th = (tcp_header *)((u_char*)ih + ip_len);//�����͸� ip���̸�ŭ �Ű��ش�.
											  /* ����Ʈ ������ ȣ��Ʈ ��Ʈ��ũ ����Ʈ ���� �� ��ȯ */

	sport = ntohs(th->sport);
	dport = ntohs(th->dport);

	if (ih->ip_version == 4)
	{
		/* ip�ּҿ� tcp��Ʈ�� ��� */
		printf("sIP= %d.%d.%d.%d. sP= %d \ndIP= %d.%d.%d.%d dP= %d\nsMAC= %02x.%02x.%02x.%02x.%02x.%02x \ndMAC= %02x.%02x.%02x.%02x.%02x.%02x\n\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport,
			eh->ether_dhost.byte1,
			eh->ether_dhost.byte2,
			eh->ether_dhost.byte3,
			eh->ether_dhost.byte4,
			eh->ether_dhost.byte5,
			eh->ether_dhost.byte6,
			eh->ether_shost.byte1,
			eh->ether_shost.byte2,
			eh->ether_shost.byte3,
			eh->ether_shost.byte4,
			eh->ether_shost.byte5,
			eh->ether_shost.byte6
		);
	}
}