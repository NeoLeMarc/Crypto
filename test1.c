#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <emmintrin.h>

int main(){
    uint64_t _v1[2]  = {6, 6};
    uint64_t _v2[2]  = {2, 2};
    uint64_t _out[2] = {0, 0};
    __m128i v1;
    __m128i v2;

    v1 = _mm_load_si128((__m128i *) _v1);
    v2 = _mm_load_si128((__m128i *) _v2);
    v1 = _mm_xor_si128(v1, v2);

    _mm_store_si128((__m128i *) _out, v1);

    printf("Foo: %lx\n", _out[0]);
}
