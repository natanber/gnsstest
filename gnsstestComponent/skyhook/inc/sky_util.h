/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_UTIL_H
#define SKY_UTIL_H

#include <inttypes.h>

/* trim in place
 returns the position of first non-space char
 and puts a \0 after the last char
 */
int32_t trim(char *str, int32_t slen, int32_t *end);

/* trim and clone */
int32_t trimc(char *dest, int32_t destlen, char *str, int32_t slen);

uint32_t hex2bin(char *hexstr, uint32_t hexlen, uint8_t *result, uint32_t reslen);
int32_t bin2hex(char *buff, int32_t buff_len, uint8_t *data, int32_t data_len);
int32_t get_xval(char *buff, const char *start, const char *end, char **p);

uint64_t get_timestamp_us();
uint64_t get_timestamp_ms();
uint32_t get_timestamp_sec();
int32_t get_http_timestamp(char *tbuf, uint32_t tbuf_len);

void print_buff(uint8_t *buff, uint32_t len);
int32_t sprint_buff(uint8_t *hex_buff, uint32_t hex_buff_len, uint8_t *buff, uint32_t buff_len);

void print_s(char *buff, int32_t len);
void print_ip(uint8_t *ip, uint8_t ip_type);
uint16_t calc_checksum(uint8_t *buff, int32_t buff_len);

int32_t hostname_to_ip(char * hostname, char* ip, uint16_t ip_len);

#endif

#ifdef __cplusplus
}
#endif
