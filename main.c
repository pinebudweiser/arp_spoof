#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define TIME_OUT    0xFF
#define MAX_SNAP_LEN  0xFFFF
#define NP_MODE 0
#define SIMPLE_SENDER_MAC {sender_mac[0],sender_mac[1],sender_mac[2],sender_mac[3],sender_mac[4],sender_mac[5]}

typedef struct libnet_802_3_hdr ETH;
typedef struct libnet_arp_hdr ARP;

typedef struct reqMAC{
    ETH eth1;
    ARP arp1;
}reqMAC;


static struct pcap_pkthdr* pktData;
static uint8_t* readedData;

void* thread_read_packet(char* interface);
char* get_interface_mac(char *interface);
char* get_interface_ip(char *interface);
uint8_t* str_to_mac(char* str);
uint32_t str_to_ip(char* str);

int main(int argc, char** argv)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char* interface;
    uint8_t* sender_mac;
    uint32_t sender_ip, target_ip;
    uint8_t* packet;
    pcap_t* pktDescriptor;
    pthread_t p_thread[2];

    if (argc != 4)
    {
          printf("Usage : arp_spoof <interface><sender ip><target ip>\n");
          return 1;
    }
    interface = argv[1];
    sender_mac = str_to_mac(get_interface_mac(interface));
    sender_ip = str_to_ip(argv[2]);
    target_ip = str_to_ip(argv[3]);
    pthread_create(&p_thread[0], 0, thread_read_packet, argv[1]);

    reqMAC REQ_PAC = {
        "\xFF\xFF\xFF\xFF\xFF\xFF",
        SIMPLE_SENDER_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        6,4,htons(ARPOP_REQUEST),
        SIMPLE_SENDER_MAC, htonl(str_to_ip(get_interface_ip(interface))),
        {0,0,0,0,0,0}, htonl(target_ip)
    };
    packet = &REQ_PAC;
    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, NULL);
    pcap_sendpacket(pktDescriptor, packet, 42);
    do{
        sleep(1);
    }while(1);

    return 0;
}

void* thread_read_packet(char* interface)
{
    pcap_t* pktDescriptor;
    char errBuf[PCAP_ERRBUF_SIZE];

    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, NULL);

    while(1)
    {
        if (pcap_next_ex(pktDescriptor, &pktData, &readedData) == 1)
        {
            printf("test");
        }
        sleep(1);
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
