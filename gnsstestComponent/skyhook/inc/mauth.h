//#ifdef __cplusplus
//extern "C" {
//#endif

#ifndef SKY_MAUTH_H
#define SKY_MAUTH_H

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "hmac256.h"

#define KEY_SIZE 64
#define MESSAGE_SIZE 64
#define HMAC_SIZE 32
#define IV_SIZE 16

void sha(uint8_t *clrtext, uint8_t *ciph);
void hmac(char *k, int32_t k_len, char *m, uint8_t *ciph);
void pad_array_with(char pad, char *array, size_t sz);
bool check(char *k, int32_t k_len, char *m, uint8_t *mac);

#endif

//#ifdef __cplusplus
//}
//#endif
