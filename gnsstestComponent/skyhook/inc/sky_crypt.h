/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SKY_CRYPT_H
#define SKY_CRYPT_H

#include "sky_protocol.h"

/* generate initialization vector */
void sky_gen_iv(uint8_t *iv);

/* encrypt data */
int32_t sky_aes_encrypt(uint8_t *data, uint32_t data_len, uint8_t *key,
        uint8_t *iv);

/* decrypt data */
int32_t sky_aes_decrypt(uint8_t *data, uint32_t data_len, uint8_t *key,
        uint8_t *iv);

uint16_t fletcher16(uint8_t const *buff, int32_t buff_len);

#endif

#ifdef __cplusplus
}
#endif
