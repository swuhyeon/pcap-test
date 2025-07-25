#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>

// Ethernet Header
struct Ethernet {
    uint8_t dst_mac[6]; // Destination MAC Address
    uint8_t src_mac[6]; // Source MAC Address
    uint16_t ethertype; // EtherType
} __attribute__((packed));

// IP Header
struct IP {
    uint8_t ver_ihl;    // Version + IHL
    uint8_t tos;        // TOS
    uint16_t total_len; // Total Length
    uint16_t id;       // Identification
    uint16_t frag_off;  // Flags + Fragment Offset
    uint8_t ttl;        // TTL
    uint8_t protocol;   // Protocol
    uint16_t checksum;  // Header Checksum
    uint8_t src_ip[4];  // Source Address
    uint8_t dst_ip[4];  // Destination Address
} __attribute__((packed));

// TCP Header
struct TCP {
    uint16_t src_port;   // Source Port
    uint16_t dst_port;   // Destination Port
    uint32_t seq_num;    // Sequence Number
    uint32_t ack_num;    // Acknowledgement Number
    uint8_t data_off;    // Data Offset + Reserved
    uint8_t flags;       // CWR + ECE + URG + ACK + PSH + RST + SYN + FIN
    uint16_t window;     // Window
    uint16_t checksum;   // Checksum
    uint16_t urgent_ptr; // Urgent Pointer
} __attribute__((packed));
