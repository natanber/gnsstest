/************************************************
 * Authors: Istvan Sleder and Marwan Kallal
 * 
 * Company: Skyhook Wireless
 *
 ************************************************/
#include "mauth.h"

#define IN_PAD 0x36
#define OUT_PAD 0x5C
#define BLOCK_SIZE 64
#define OUTPUT_SIZE 32
#define MAX_HASH_SIZE 4

typedef struct key_io {
    char k_str_in[BLOCK_SIZE];
    char k_str_out[BLOCK_SIZE];
} key_io;

void hmac(char *k, int32_t k_len, char *m, uint8_t *ciph) {
    key_io keys;
    memcpy(&keys, k, BLOCK_SIZE);

    keys.k_str_in[BLOCK_SIZE - 1] = '\0';
    keys.k_str_out[BLOCK_SIZE - 1] = '\0';

    pad_array_with(IN_PAD, keys.k_str_in, strlen(keys.k_str_in));
    pad_array_with(OUT_PAD, keys.k_str_out, strlen(keys.k_str_out));

    //MUST BE BLOCK SIZE (size of data element)
    //Compiler differences will init memory differently and things WILL break.
    char strt_str[BLOCK_SIZE + MESSAGE_SIZE];

    uint8_t in_ciph[BLOCK_SIZE];
    sha((uint8_t *) memcpy(strt_str, m, MESSAGE_SIZE), in_ciph);

    char h_in[BLOCK_SIZE + MESSAGE_SIZE];
    memcpy(h_in, keys.k_str_out, BLOCK_SIZE);
    memcpy(h_in + BLOCK_SIZE, (char *) in_ciph, BLOCK_SIZE);
    sha((uint8_t *) h_in, ciph);
}

void pad_array_with(char pad, char *array, size_t sz) {
    int32_t i;
    for (i = sz; i-- > 0;) {
        array[i] = array[i] ^ pad;
    }
}

void sha(uint8_t *clrtext, uint8_t ciph[]) {
    SHA256_CTX ctx;

    hmac256_init(&ctx);
    hmac256_update(&ctx, clrtext, strlen((char *) clrtext));
    hmac256_final(&ctx, ciph);
}
