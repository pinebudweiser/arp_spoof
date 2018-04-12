#include <libnet.h>
#include <stdint.h>

#define TIME_OUT        0x0
#define MAX_SNAP_LEN    0xFFFF
#define NP_MODE         0
#define NET_IP_LEN      0x4

#pragma pack(push, 1)
typedef struct libnet_802_3_hdr ETH;
typedef struct ARP{
    struct libnet_arp_hdr arpHeader;
    uint8_t srcMAC[ETHER_ADDR_LEN];
    uint32_t srcIP;
    uint8_t dstMAC[ETHER_ADDR_LEN];
    uint32_t dstIP;
}ARP;
typedef struct libnet_ipv4_hdr IP;
typedef struct ETH_ARP{
    ETH ethHeader;
    ARP arpHeader;
}ETH_ARP;
typedef struct SHD{
    uint8_t localhostMAC[ETHER_ADDR_LEN];
    uint8_t senderMAC[ETHER_ADDR_LEN];
    uint8_t targetMAC[ETHER_ADDR_LEN];
    uint32_t senderIP;
    uint32_t targetIP;
    uint32_t localhostIP;
}SHD;
#pragma pack(pop)
