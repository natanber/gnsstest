/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "sky_crypt.h"
#include "mauth.h"
#include "aes.h"

// iv must be 16 byte long
void sky_gen_iv(uint8_t *iv) {
    char key[KEY_SIZE];
    char mes[MESSAGE_SIZE];
    int32_t i;
    for (i = 0; i < KEY_SIZE; i++) {
        key[i] = rand() % 256;
    }
    for (i = 0; i < MESSAGE_SIZE; i++) {
        mes[i] = rand() % 256;
    }

    unsigned char iv__[HMAC_SIZE];
    memset(iv__, 0, HMAC_SIZE);
    hmac(key, KEY_SIZE, mes, iv__);
    memcpy(iv, iv__, IV_SIZE);
}

// iv and key must be 16 byte long
int32_t sky_aes_encrypt(uint8_t *data, uint32_t data_len, uint8_t *key,
        uint8_t *iv) {
    if (data_len & 0x0F) {
        perror("Data length (in bytes) must be a multiple of 16");
        return -1;
    }

    uint8_t output[data_len];
    AES128_CBC_encrypt_buffer(output, data, data_len, key, iv);
    memcpy(data, output, data_len);
    return 0;
}

// iv and key must be 16 byte long
int32_t sky_aes_decrypt(uint8_t *data, uint32_t data_len, uint8_t *key,
        uint8_t *iv) {
    if (data_len & 0x0F) {
        perror("non 16 byte blocks");
        return -1;
    }

    uint8_t output[data_len];
    AES128_CBC_decrypt_buffer(output, data, data_len, key, iv);
    memcpy(data, output, data_len);
    return 0;
}

// http://en.wikipedia.org/wiki/Fletcher%27s_checksum
uint16_t fletcher16(uint8_t const *buff, int32_t buff_len) {
    uint16_t s1, s2;
    s1 = s2 = 0xFF;

    while (buff_len) {
        int32_t len = buff_len > 20 ? 20 : buff_len;

        buff_len -= len;

        do {
            s2 += s1 += *buff++;
        } while (--len);

        s1 = (s1 & 0xFF) + (s1 >> 8);
        s2 = (s2 & 0xFF) + (s2 >> 8);
    }

    /* Second reduction step to reduce sums to 8 bits */
    s1 = (s1 & 0xFF) + (s1 >> 8);
    s2 = (s2 & 0xFF) + (s2 >> 8);

    return s2 << 8 | s1;
}
