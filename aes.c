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

void encrypt(char *, char *, char *);

void main(){
    char key[17] = {'S', 'e', 'c', 'r', 'e', 't'};
    char message[17] =  {'C', 'l', 'e', 'a', 'r', 't', 'e', 'x', 't'};
    char out[17];

    encrypt(message, key, out);

    // Terminate strings
    key[16] = '\0';
    out[16] = '\0';
    message[16] = '\0';

    printf("Message: %s\n", message);
    printf("Key: %s\n", key);
    printf("Crypt: %s\n", out);
}

void encrypt(char * message, char * key, char * out){
    // Key expansion: 
    // Generate key for each round
    // 128bit Keylength -> 11 rounds
    __m128i * _k = (__m128i *)key;
    __m128i K0  = _mm_load_si128((__m128i *)(_k));
    __m128i K1  = KEYEXP(K0, 0x01);
    __m128i K2  = KEYEXP(K1, 0x02);
    __m128i K3  = KEYEXP(K2, 0x04);
    __m128i K4  = KEYEXP(K3, 0x08);
    __m128i K5  = KEYEXP(K4, 0x10);
    __m128i K6  = KEYEXP(K5, 0x20);
    __m128i K7  = KEYEXP(K6, 0x40);
    __m128i K8  = KEYEXP(K7, 0x80);
    __m128i K9  = KEYEXP(K8, 0x1B);
    __m128i K10 = KEYEXP(K9, 0x36);

    // Load message into m
    __m128i m = _mm_load_si128((const __m128i *) message);

    // 1. Round = message XOR key
    m = _mm_xor_si128(m, K0);

    // 9 rounds of AESENC
    m = _mm_aesenc_si128(m, K1);
    m = _mm_aesenc_si128(m, K2);
    m = _mm_aesenc_si128(m, K3);
    m = _mm_aesenc_si128(m, K4);
    m = _mm_aesenc_si128(m, K5);
    m = _mm_aesenc_si128(m, K6);
    m = _mm_aesenc_si128(m, K7);
    m = _mm_aesenc_si128(m, K8);
    m = _mm_aesenc_si128(m, K9);

    // Last round is done with AESENCLAST
    m = _mm_aesenclast_si128(m, K10);

    // Store result in out variable
    _mm_store_si128((__m128i *) out, m);
}
