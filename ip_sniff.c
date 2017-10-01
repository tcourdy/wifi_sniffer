#include<stdio.h>
#include<pcap.h>
//#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<netdb.h>
#include<string.h>

/* Compile command gcc -Wall -o sniffex main.c -l pcap */


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define NUM_PACKETS -1

/* IP header */
struct sniff_ip {
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
  #define IP_RF 0x8000		/* reserved fragment flag */
  #define IP_DF 0x4000		/* dont fragment flag */
  #define IP_MF 0x2000		/* more fragments flag */
  #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;		/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main() {
  pcap_t *handle;
  struct bpf_program bpf_filter;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev;
  char filter[] = "ip";

  // notes for dns filter
  // dns uses UDP and port 53

  //lookup network device to sniff on
  dev = pcap_lookupdev(errbuf);
  if(dev == NULL) {
    fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
    return(2);
  }
  printf("Device: %s\n", dev);

  // lookup network number and netmask
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Can't get netmask for device %s\n", dev);
    net = PCAP_NETMASK_UNKNOWN;
    mask = PCAP_NETMASK_UNKNOWN;
  }

  //create a handle to use for sniffing (promiscuous mode)
  handle = pcap_open_live(dev, 1518, 1, 1000, errbuf);
  if(handle == NULL) {
    fprintf(stderr, "Couldn't create pcap handle: %s\n", errbuf);
    return(2);
  }

  // make sure the device provides ethernet link layer headers
  if(pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers\n", dev);
    return(2);
  }

  // compile our filter so it can be applied to the handle
  if(pcap_compile(handle, &bpf_filter, filter, 0, net) == -1) {
    fprintf(stderr, "Couldn't compile filter. %s\n", pcap_geterr(handle));
    return(2);
  }

  //apply the filter to the handle
  if(pcap_setfilter(handle, &bpf_filter) == -1) {
    fprintf(stderr, "Couldn't apply filter to handle. %s\n", pcap_geterr(handle));
    return(2);
  }

  pcap_loop(handle, NUM_PACKETS, got_packet, NULL);
  

  return(0);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ip *ip;              /* The IP header */
  struct sockaddr_in sa_src;
  struct sockaddr_in sa_dst;
  printf("args: %s\n", args);

  int err;

  char host[NI_MAXHOST];

  char host_dst[NI_MAXHOST];

	int size_ip;
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

  if(strcmp(inet_ntoa(ip->ip_dst), "192.168.0.1") == 0
     || strcmp(inet_ntoa(ip->ip_src), "192.168.0.1") == 0) {
    return;
  }

  printf("\nPacket number %d:\n", count);
	count++;

  sa_src.sin_family = AF_INET;
  sa_src.sin_port = htons(80);
  sa_src.sin_addr = ip->ip_src;

  err = getnameinfo((struct sockaddr*)&sa_src, sizeof(sa_src),
                    host, sizeof(host),
                    NULL, 0, 0);
  if(err) {
    fprintf(stderr, "getnameinfo: %s\n", gai_strerror(err));
    printf("From: %s, %s\n", inet_ntoa(ip->ip_src), "could not resolve host name");    
  } else {
    printf("From: %s, %s\n", inet_ntoa(ip->ip_src), host);    
  }

  sa_dst.sin_family = AF_INET;
  sa_dst.sin_port = htons(80);
  sa_dst.sin_addr = ip->ip_dst;

  err = getnameinfo((struct sockaddr*)&sa_dst, sizeof(sa_dst),
                    host_dst, sizeof(host_dst),
                    NULL, 0, 0);
  if(err) {
    fprintf(stderr, "getnameinfo: %s\n", gai_strerror(err));
    printf("To: %s, %s\n", inet_ntoa(ip->ip_dst), "could not resolve host name");    
  } else {
    printf("To: %s, %s\n", inet_ntoa(ip->ip_dst), host_dst);    
  }
}
