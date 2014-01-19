aes: aes.c
	gcc -maes -mfpmath=sse -mmmx -msse -msse2 aes.c -o aes
