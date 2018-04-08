#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <stdlib.h>
#include <unistd.h>

#define TIME_OUT    0xFF
#define MAX_SNAP_LEN  0xFFFF
#define NP_MODE 0

typedef struct libnet_802_3_hdr ETH;
typedef struct libnet_arp_hdr ARP;

static struct pcap_pkthdr* pktData;
static uint8_t* readedData;

void* thread_read_packet(char* interface);
char* get_interface_mac(char *interface);

int main(int argc, char** argv)
{
    pthread_t p_thread[2];
    typedef struct reqMAC{
        ARP A1;
        ETH E1;
    }reqMAC;

    pthread_create(&p_thread[0], 0, thread_read_packet, argv[1]);

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
