#include "pcap-test.h"

void usage() {
  printf("syntax: pcap-test <interface>\n");
  printf("sample: pcap-test wlan0\n");
}

typedef struct {
  char* dev_;
} Param;

Param param = {
  .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return false;
  }
  param->dev_ = argv[1];
  return true;
}

// print ethernet info
void find_ethernet(char* str, uint8_t* eth) {
  printf("%s", str);
  for (int i=0; i<6; i++) {
    printf("%02x", eth[i]);
    if (i<5) printf(":");
  }
  printf("\n");
}

// print ip info
void find_ip(char* str, uint8_t* ip) {
  printf("%s", str);
  for (int i=0; i<4; i++) {
    printf("%d", ip[i]);
    if (i<3) printf(".");
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  if (!parse(&param, argc, argv))
    return -1;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
  if (pcap == NULL) {
    fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
    return -1;
  }

  // struct variable declaration
  struct Ethernet* ethernet;
  struct IP* ip;
  struct TCP* tcp;

  int count = 0;

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(pcap, &header, &packet);
    if (res == 0) continue;
    if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
      break;
    }

    ethernet = (struct Ethernet*)packet;
    // IPv4 Check
    if (ntohs(ethernet->ethertype) != 0x0800)
      continue;

    ip = (struct IP*)(packet + sizeof(struct Ethernet));
    // TCP Check
    if (ip->protocol != 6)
      continue;
    int ip_header_len = (ip->ver_ihl & 0x0F) * 4;

    tcp = (struct TCP*)(packet + sizeof(struct Ethernet) + ip_header_len);
    int tcp_header_len = ((tcp->data_off & 0xF0) >> 4) * 4;

    // ip->total_len instead of header->caplen
    int payload_len = ntohs(ip->total_len) - ip_header_len - tcp_header_len;
    const uint8_t* payload = packet + sizeof(struct Ethernet) + ip_header_len + tcp_header_len;

    printf("%d packet\n", ++count);
    printf("==================================================\n");

    find_ethernet("Ethernet Header src mac: ", ethernet->src_mac);
    find_ethernet("Ethernet Header dst mac: ", ethernet->dst_mac);

    find_ip("IP Header src ip: ", ip->src_ip);
    find_ip("IP Header dst ip: ", ip->dst_ip);

    printf("TCP Header src port: %d\n", ntohs(tcp->src_port));
    printf("TCP Header dst port: %d\n", ntohs(tcp->dst_port));

    printf("Payload Data in hex (up to 20 bytes): ");
    if (payload_len>0) {
      for (int i=0; i<payload_len && i<20; i++) {
        printf("%02x", payload[i]);
        if (i<payload_len-1 && i<19) printf("|");
      }
    }
    else {
      printf("-");
    }
    printf("\n\n");
  }

  pcap_close(pcap);
}
