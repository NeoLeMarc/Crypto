#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wmmintrin.h>

__m128i aes128_keyexpand(__m128i key, __m128i keygened){
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
    return _mm_xor_si128(key, keygened);
}

#define KEYEXP(K, I) aes128_keyexpand(K, (__m128i)_mm_aeskeygenassist_si128(K, I))

void encrypt128(char * message, __m128i * K, char * out);
void decrypt128(char * encrypted, __m128i * K, char * out);
void expandkey128(char * key, __m128i * K);
void p(char *, char *);

void main(){
    char key[16] = {'S', 'e', 'c', 'r', 'e', 't', 's', 'F', 'o'};
    char message[16] =  {'C', 'l', 'e', 'a', 'r', 't', 'e', 'x', 't'};
    char out[16];
    char decrypted[16];
    char buf[17];

    __m128i K[21];
    expandkey128(key, K);
    encrypt128(message, K, out);
    decrypt128(out, K, decrypted);

    p("Message", message);
    p("Key", key);
    p("Crypt", out);
    p("Decrypted", decrypted);
}

void p(char * message, char * param){
    char buf[17];
    memcpy(buf, param, 16*sizeof(char));
    buf[16] = '\0';
    printf("%s: %s\n", message, buf);
}

void expandkey128(char * key, __m128i * K){
    // Key expansion: 
    // Generate key for each round
    // 128bit Keylength -> 11 rounds
    __m128i * _k = (__m128i *)key;
    K[0]  = _mm_load_si128((__m128i *)(_k));
    K[1]  = KEYEXP(K[0], 0x01);
    K[2]  = KEYEXP(K[1], 0x02);
    K[3]  = KEYEXP(K[2], 0x04);
    K[4]  = KEYEXP(K[3], 0x08);
    K[5]  = KEYEXP(K[4], 0x10);
    K[6]  = KEYEXP(K[5], 0x20);
    K[7]  = KEYEXP(K[6], 0x40);
    K[8]  = KEYEXP(K[7], 0x80);
    K[9]  = KEYEXP(K[8], 0x1B);
    K[10] = KEYEXP(K[9], 0x36); // Used for last round of encryption
                                // and first round of decryption

    // Decryption keys
    K[11] = _mm_aesimc_si128(K[9]);
    K[12] = _mm_aesimc_si128(K[8]);
    K[13] = _mm_aesimc_si128(K[7]);
    K[14] = _mm_aesimc_si128(K[6]);
    K[15] = _mm_aesimc_si128(K[5]);
    K[16] = _mm_aesimc_si128(K[4]);
    K[17] = _mm_aesimc_si128(K[3]);
    K[18] = _mm_aesimc_si128(K[2]);
    K[19] = _mm_aesimc_si128(K[1]);
    K[20] = K[0];
}

void encrypt128(char * message, __m128i * K, char * out){
    // Load message into m
    __m128i m = _mm_load_si128((const __m128i *) message);

    // 1. Round = message XOR key
    m = _mm_xor_si128(m, K[0]);

    // 9 rounds of AESENC
    m = _mm_aesenc_si128(m, K[1]);
    m = _mm_aesenc_si128(m, K[2]);
    m = _mm_aesenc_si128(m, K[3]);
    m = _mm_aesenc_si128(m, K[4]);
    m = _mm_aesenc_si128(m, K[5]);
    m = _mm_aesenc_si128(m, K[6]);
    m = _mm_aesenc_si128(m, K[7]);
    m = _mm_aesenc_si128(m, K[8]);
    m = _mm_aesenc_si128(m, K[9]);

    // Last round is done with AESENCLAST
    m = _mm_aesenclast_si128(m, K[10]);

    // Store result in out variable
    _mm_store_si128((__m128i *) out, m);
}

void decrypt128(char * encrypted, __m128i * K, char * out){
    // Load encrypted message into c 
    __m128i c = _mm_load_si128((const __m128i *) encrypted);

    // 1. Round = crypt XOR key
    c = _mm_xor_si128(c, K[10]);

    // 9 rounds of AESDEC
    c = _mm_aesdec_si128(c, K[11]);
    c = _mm_aesdec_si128(c, K[12]);
    c = _mm_aesdec_si128(c, K[13]);
    c = _mm_aesdec_si128(c, K[14]);
    c = _mm_aesdec_si128(c, K[15]);
    c = _mm_aesdec_si128(c, K[16]);
    c = _mm_aesdec_si128(c, K[17]);
    c = _mm_aesdec_si128(c, K[18]);
    c = _mm_aesdec_si128(c, K[19]);

    // Last round is done with AESDECLAST
    c = _mm_aesdeclast_si128(c, K[20]);

    // Store result in out variable
    _mm_store_si128((__m128i *) out, c);
}
