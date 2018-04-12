#include <stdint.h>

char strMAC[18];
uint8_t byteMAC[6];
char strIP[15];

char* get_interface_mac(char *interface);
char* get_interface_ip(char *interface);
uint8_t* str_to_mac(char* str);
uint32_t str_to_ip(char* str);
