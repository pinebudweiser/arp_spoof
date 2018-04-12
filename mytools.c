#include <stdio.h>
#include <string.h>
#include "mytools.h"

char* get_interface_mac(char *interface)
{
    FILE* fileDescriptor;
    char buf[100];

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
    sscanf(str,"%02x:%02x:%02x:%02x:%02x:%02x"
           ,&byteMAC[0],&byteMAC[1],&byteMAC[2],&byteMAC[3],&byteMAC[4],&byteMAC[5]);

    return byteMAC;
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
