aes: aes.S
	gcc aes.S -o aes

aes.S: aes.c
	gcc -maes -mfpmath=sse -mmmx -msse -msse2 aes.c -S -o aes.S
