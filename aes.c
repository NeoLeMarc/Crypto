#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wmmintrin.h>

// RCON is the exponentiation of 2 to a specific value.  Note that this operation is not performed 
// with regular integers but in Rijanandels finite field GF(2^8). 
// RCON[i] = x^(i-1) mod x^8 + x^4 + x^3 + x + 1
uint8_t RCON[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d};

// Note: AESKEYGENASSIST requires the RCON value to be immediate
// therefore we can't use the array above
#define RCON_1  0x01
#define RCON_2  0x02
#define RCON_3  0x04
#define RCON_4  0x08
#define RCON_5  0x10
#define RCON_6  0x20
#define RCON_7  0x40
#define RCON_8  0x80
#define RCON_9  0x1b
#define RCON_10 0x36

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
    // The message that will be encrypted (128bit)
    char message[16] =  {'C', 'l', 'e', 'a', 'r', 't', 'e', 'x', 't'};

    // Key (128bit)
    char key[16] = {'S', 'e', 'c', 'r', 'e', 't', 's', 'F', 'o'};

    // Encrypted Text
    char encrypted[16];

    // Decrypted text
    char decrypted[16];

    // Expanded key for encryption & decryption
    __m128i K[21];

    expandkey128(key, K);
    encrypt128(message, K, encrypted);
    decrypt128(encrypted, K, decrypted);

    // Verify operation
    p("Message", message);
    p("Key", key);
    p("Crypt", encrypted);
    p("Decrypted", decrypted);
}

void p(char * message, char * param){
    char buf[17];
    memcpy(buf, param, 16*sizeof(char));
    buf[16] = '\0';
    printf("%s: %s\n", message, buf);
}

void expandkey128(char * key, __m128i * K){
    /* Key expansion: 
       Generate key for each round
       128bit Keylength -> 11 rounds */

    // The key for the first round (XOR) is just
    // the plain encryption key
    K[0]  = _mm_load_si128((__m128i *)(key));

    // KEYEXP is a macro that returns the key
    // for the given round. The second parameter is the
    // RCON value for that round. 
    K[1]  = KEYEXP(K[0], RCON_1);
    K[2]  = KEYEXP(K[1], RCON_2);
    K[3]  = KEYEXP(K[2], RCON_3);
    K[4]  = KEYEXP(K[3], RCON_4);
    K[5]  = KEYEXP(K[4], RCON_5);
    K[6]  = KEYEXP(K[5], RCON_6);
    K[7]  = KEYEXP(K[6], RCON_7);
    K[8]  = KEYEXP(K[7], RCON_8);
    K[9]  = KEYEXP(K[8], RCON_9);

    // K[10] is used for the last round of encryption
    // as well as the first round (XOR) of decryption
    K[10] = KEYEXP(K[9], RCON_10); 

    // Decryption keys. Those are the inverse of the encryption keys
    // generated with AESIMC.
    K[11] = _mm_aesimc_si128(K[9]);
    K[12] = _mm_aesimc_si128(K[8]);
    K[13] = _mm_aesimc_si128(K[7]);
    K[14] = _mm_aesimc_si128(K[6]);
    K[15] = _mm_aesimc_si128(K[5]);
    K[16] = _mm_aesimc_si128(K[4]);
    K[17] = _mm_aesimc_si128(K[3]);
    K[18] = _mm_aesimc_si128(K[2]);
    K[19] = _mm_aesimc_si128(K[1]);

    // The last decryption key is just the plain encryption key
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
