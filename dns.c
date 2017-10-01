#include <stdio.h>
#include <stdint.h>
#include <features.h>
#include <pcap.h>
#include <net/if.h>
//#include<netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <netinet/ip.h>

// Compile with gcc -Wall -fPIC dns.c -l pcap

/* Ethernet header are 14 bytes */
#define ETH_HLEN 14
#define NUM_PACKETS 1000

struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

void got_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data);
static u_char *dns_label_to_str(u_char **label, u_char *dest,
                                size_t dest_size,
                                const u_char *payload,
                                const u_char *end);

static u_char *skip_dns_label(u_char *label);

int main() {
  pcap_t *handle;
  struct bpf_program bpf_filter;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev;
  char filter[] = "port 53 and udp";

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
  //handle = pcap_open_live(dev, 1518, 1, 1000, errbuf);
  handle = pcap_create(dev, errbuf);

  if(handle == NULL) {
    fprintf(stderr, "Couldn't create pcap handle: %s\n", errbuf);
    return(2);
  }

  if(pcap_set_snaplen(handle, 1518)) {
    fprintf(stderr, "Couldn't set snaplen: %s\n", errbuf);
    return(2);
  }
  
  if(pcap_set_timeout(handle, 1000)){
    fprintf(stderr, "Couldn't set timeout: %s\n", errbuf);
    return(2);
  }
  
  if(pcap_set_promisc(handle, 1)){
    fprintf(stderr, "Couldn't set promiscuous mode: %s\n", errbuf);
    return(2);
  }
  
  /* if(pcap_set_rfmon(handle, 1)) { */
  /*   fprintf(stderr, "Can't set rfmon, pcap_set_rfmon:%s\n", errbuf); */
  /*   return(2); */
  /* } */

  if(pcap_activate(handle)) {
    fprintf(stderr, "Can't activate pcap handle:%s\n", errbuf);
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


void got_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data) {
  static int count = 1;
  const u_char *pkt = data;
  struct dnshdr *dnsh;
  u_char *tmp;
  u_char *label;
  const u_char *end;
  uint16_t qtype = 0;
  int i;
  u_char buf[BUFSIZ];

  pkt += ETH_HLEN;
  // skip past the ip header
  pkt = pkt + (((struct iphdr *)pkt)->ihl << 2);
  // skip past udp header
  pkt += 8;

  //TODO: deal with dns over tcp

  end = pkt + (hdr->len - (pkt - data));
  dnsh = (struct dnshdr *)(pkt);
  tmp = (u_char *)(pkt + 12); // skip past the query id and the query flags

  for (i = 0; i < dnsh->qdcount; i++) {
		/* Get the first question's label and question type */
		if (!qtype) {
			label = dns_label_to_str(&tmp, buf, BUFSIZ, pkt, end);
			tmp++;
			qtype = ntohs(*(uint16_t *)tmp);
		} else {
			if (*tmp & 0xc0) tmp += 2;
			else tmp = skip_dns_label(tmp);
		}

		/* Skip type and class */
		tmp += 4;
	}
  printf("Packet#:%d -- DNS Label: %-30s\n", count++, label);
}


/**
 * Convert a DNS label (which may contain pointers) to
 * a string by way of the given destination buffer.
 *
 * \param[in] label     Pointer to the start of the label
 * \param[in] dest      Destination buffer
 * \param[in] dest_size Destination buffer size
 * \param[in] payload   Start of the packet
 * \param[in] end       End of the packet
 * \return dest
 */
static u_char *dns_label_to_str(u_char **label, u_char *dest,
                               size_t dest_size,
                               const u_char *payload,
                               const u_char *end)
{
	u_char *tmp, *dst = dest;

	if (!label || !*label || !dest)
		goto err;

	*dest = '\0';
	while (*label < end && **label) {
		if (**label & 0xc0) { /* Pointer */
			tmp = (u_char *)payload;
			tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
			while (tmp < end && *tmp) {
				if (dst + *tmp >= dest + dest_size)
					goto err;
				memcpy(dst, tmp+1, *tmp);
				dst += *tmp; tmp += *tmp + 1;
				if (dst > dest + dest_size) goto err;
				*dst = '.'; dst++;
			};
			*label += 2;
		} else { /* Label */
			if ((*label + **label) >= end)
				goto err;
			if (**label + dst >= dest + dest_size)
				goto err;
			memcpy(dst, *label + 1, **label);
			dst += **label;
			if (dst > dest + dest_size) goto err;
			*label += **label + 1;
			*dst = '.'; dst++;
		}
	}

	*(--dst) = '\0';
	return dest;
err:
	if (dest) *dest = '\0';
	return dest;
}


static u_char *skip_dns_label(u_char *label)
{
	u_char *tmp;

	if (!label) return NULL;
	if (*label & 0xc0)
		return label + 2;

	tmp = label;
	while (*label) {
		tmp += *label + 1;
		label = tmp;
	}
	return label + 1;
}
