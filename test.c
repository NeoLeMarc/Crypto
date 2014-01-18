#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wmmintrin.h>

/*
char * AESKEYGENASSIST(char * key, int round){
    char * output = (char *)malloc(17);
    asm("movups %1, %%xmm0; AESKEYGENASSIST $0x1, %%xmm0, %%xmm1; movups %%xmm1, %0"
            : "=r"(output)
            : "m"(key), "r"(round)
            : "%xmm0");
    output[16] = '\0';
    return output;
}
*/

char * AESKEYGENASSIST(char * key, int round){
    return __mm_aesimc_si128(key, round);
}

int main(){
    printf("Hello world!\n");

    int a = 1, b = 2, c;

    asm("movl %1, %%eax; add %2, %%eax; movl %%eax, %0;"
         : "=r"(c)   /* output */
         : "r"(a), "r"(b) /* input */ 
         : "%eax"    /* clobbered register */
       );

    printf("Value of c: %i\n", c);

    char key[17] = "1234567890123456";
    char * output;

    *output = ASMKEYGENASSIST(key, 1);
    printf("ASMKEYGENASSIST returned %s\n", output);
    free(output);
}
