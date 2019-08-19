/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "sky_protocol.h"
#include "sky_util.h"

/* str -- string to be trimmed
 slen -- lenght of str
 end -- output of end pos
 returns -- start pos
 returns the position of first non-space char
 and the last position in the end var
 and puts a \0 after the last non-space char
 */
int32_t trim(char *str, int32_t slen, int32_t *end) {
    int32_t i, j;

    int32_t start = -1;
    *end = -1;

    for (i = 0, j = slen - 1; i < slen; i++, j--) {
        if (start == -1 && !isspace((int32_t )str[i]))
            start = i;

        if (*end == -1 && str[j] != '\0' && !isspace((int32_t )str[j])) {
            *end = j + 1;
            if (j < slen)
                str[*end] = '\0';
        }

        if (start > -1 && *end > -1)
            break;
    }

    return start;
}
/*  str -- input string
 slen -- input string len
 dest -- pointer to target buffer
 destlen -- target buffer size
 return -- trimmed string length or error
 copies the trimmed string into the dest buffer
 */
int32_t trimc(char *dest, int32_t destlen, char *str, int32_t slen) {
    int32_t end;
    int32_t start = trim(str, slen, &end);

    if (slen < end - start)
        return -1;
    if (destlen < slen)
        return -1;

    strncpy(dest, &str[start], destlen);
    return end - start;
}

int32_t bin2hex(char *buff, int32_t buff_len, uint8_t *data, int32_t data_len) {
    const char * hex = "0123456789ABCDEF";

    char *p;
    int32_t i;

    if (buff_len < 2 * data_len)
        return -1;

    p = buff;

    for (i = 0; i < data_len; i++) {
        *p++ = hex[data[i] >> 4 & 0x0F];
        *p++ = hex[data[i] & 0x0F];
    }

    return 0;
}

/* returns number of result bytes that were successfully parsed */
uint32_t hex2bin(char *hexstr, uint32_t hexlen, uint8_t *result, uint32_t reslen) {
    uint32_t i, j = 0, k = 0;

    for (i = 0; i < hexlen; i++) {
        uint8_t c = (uint8_t) hexstr[i];

        if (c >= '0' && c <= '9')
            c -= '0';
        else if (c >= 'a' && c <= 'f')
            c = (uint8_t) ((c - 'a') + 10);
        else if (c >= 'A' && c <= 'F')
            c = (uint8_t) ((c - 'A') + 10);
        else
            continue;

        // assign every other hex byte to lower or upper 4 bit
        if (k++ & 0x01)
            result[j++] |= c;
        else
            result[j] = c << 4;

        if (j >= reslen)
            break;
    }

    return j;
}

uint64_t get_timestamp_us() {
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t ts = now.tv_sec;
    return ts * 1000000 + now.tv_usec;
}

uint32_t get_timestamp_sec() {
    struct timeval now;
    gettimeofday(&now, NULL);

    uint32_t tstmp = (uint32_t) (now.tv_sec);
    if (now.tv_usec > 500000)
        tstmp++; // round up
    return tstmp;
}

uint64_t get_timestamp_ms() {
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t ts = now.tv_sec;
    return ts * 1000 + now.tv_usec / 1000;
}

int32_t get_http_timestamp(char *tbuf, uint32_t tbuf_len) {
    time_t now = time(0);
    struct tm tm = *gmtime(&now);

    return strftime(tbuf, tbuf_len, "%a, %d %b %Y %H:%M:%S %Z", &tm);
}

int32_t sprint_buff(uint8_t *hex_buff, uint32_t hex_buff_len, uint8_t *buff, uint32_t buff_len) {
    uint32_t i;
    char *p = (char *)hex_buff;
    uint32_t total = buff_len * 3;

    if (hex_buff_len < total)
        return -1;

    for (i = 0; i < buff_len; ++i) {
        p += sprintf(p, "%02X ", buff[i]);
    }
    *(p - 1) = '\0'; // overwrite the last space by \0.
    return (int32_t) (p - (char *)hex_buff);
}

void print_buff(uint8_t *buff, uint32_t len) {
    uint32_t i;
    uint32_t j = 0;

    for (i = 0; i < len; i++) {
        printf("%02X ", buff[i]);

        if (++j > 15) {
            j = 0;
            printf("\n");
        }
    }
    printf("\n");
}

/* search buff for start and end tags
 * resultant string pointer is in p
 * length returned
 */
int32_t get_xval(char *buff, const char *start, const char *end, char **p) {
    if (buff == NULL)
        return -1;

    char *p1, *p2;
    int32_t stlen = (int32_t) strlen(start);

    p1 = strstr(buff, start);
    if (p1 == NULL)
        return 0;

    p2 = strstr(p1 + stlen, end); // continue from start

    if (p2 == NULL)
        return 0;
    *p = p1 + stlen;

    return (int32_t) (p2 - *p);
}

void print_s(char *buff, int32_t len) {
    int32_t i;
    for (i = 0; i < len; i++) {
        printf("%c", buff[i]);
    }
    printf("\n");
}

void print_ip(uint8_t *ip, uint8_t ip_type) {
    if (ip == NULL)
        return;

    int32_t i;

    if (ip_type == DATA_TYPE_IPV6) {
        char z = 0;

        for (i = 0; i < 8; i++) {
            if (ip[i] == 0 && ip[i + 1] == 0) {
                z = 1;
                continue;
            }

            if (z)
                printf(":");
            printf("%02x", ip[i]);
            printf("%02x", ip[i + 1]);
            printf(":");
            z = 0;
        }
    } else {
        for (i = 0; i < 4; i++) {
            printf("%d", ip[i]);
            if (i < 3)
                printf(".");
        }
    }
    printf("\n");
}

uint16_t calc_checksum(uint8_t *buff, int32_t buff_len) {
    int32_t i;

    uint16_t chcks = 0;

    for (i = 0; i < buff_len; i++) {
        chcks += buff[i];
    }
    return chcks;
}

int32_t hostname_to_ip(char * hostname, char* ip, uint16_t ip_len) {
    struct hostent *he;
    struct in_addr **addr_list;
    int32_t i;

    if ((he = gethostbyname(hostname)) == NULL) {
        // get the host info
        herror("gethostbyname");
        return 1;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for (i = 0; addr_list[i] != NULL; i++) {
        //Return the first one;
        strncpy(ip, inet_ntoa(*addr_list[i]), ip_len);
        return 0;
    }

    return 1;
}
