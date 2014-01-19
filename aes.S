	.file	"aes.c"
	.globl	RCON
	.data
	.align 32
	.type	RCON, @object
	.size	RCON, 256
RCON:
	.byte	-115
	.byte	1
	.byte	2
	.byte	4
	.byte	8
	.byte	16
	.byte	32
	.byte	64
	.byte	-128
	.byte	27
	.byte	54
	.byte	108
	.byte	-40
	.byte	-85
	.byte	77
	.byte	-102
	.byte	47
	.byte	94
	.byte	-68
	.byte	99
	.byte	-58
	.byte	-105
	.byte	53
	.byte	106
	.byte	-44
	.byte	-77
	.byte	125
	.byte	-6
	.byte	-17
	.byte	-59
	.byte	-111
	.byte	57
	.byte	114
	.byte	-28
	.byte	-45
	.byte	-67
	.byte	97
	.byte	-62
	.byte	-97
	.byte	37
	.byte	74
	.byte	-108
	.byte	51
	.byte	102
	.byte	-52
	.byte	-125
	.byte	29
	.byte	58
	.byte	116
	.byte	-24
	.byte	-53
	.byte	-115
	.byte	1
	.byte	2
	.byte	4
	.byte	8
	.byte	16
	.byte	32
	.byte	64
	.byte	-128
	.byte	27
	.byte	54
	.byte	108
	.byte	-40
	.byte	-85
	.byte	77
	.byte	-102
	.byte	47
	.byte	94
	.byte	-68
	.byte	99
	.byte	-58
	.byte	-105
	.byte	53
	.byte	106
	.byte	-44
	.byte	-77
	.byte	125
	.byte	-6
	.byte	-17
	.byte	-59
	.byte	-111
	.byte	57
	.byte	114
	.byte	-28
	.byte	-45
	.byte	-67
	.byte	97
	.byte	-62
	.byte	-97
	.byte	37
	.byte	74
	.byte	-108
	.byte	51
	.byte	102
	.byte	-52
	.byte	-125
	.byte	29
	.byte	58
	.byte	116
	.byte	-24
	.byte	-53
	.byte	-115
	.byte	1
	.byte	2
	.byte	4
	.byte	8
	.byte	16
	.byte	32
	.byte	64
	.byte	-128
	.byte	27
	.byte	54
	.byte	108
	.byte	-40
	.byte	-85
	.byte	77
	.byte	-102
	.byte	47
	.byte	94
	.byte	-68
	.byte	99
	.byte	-58
	.byte	-105
	.byte	53
	.byte	106
	.byte	-44
	.byte	-77
	.byte	125
	.byte	-6
	.byte	-17
	.byte	-59
	.byte	-111
	.byte	57
	.byte	114
	.byte	-28
	.byte	-45
	.byte	-67
	.byte	97
	.byte	-62
	.byte	-97
	.byte	37
	.byte	74
	.byte	-108
	.byte	51
	.byte	102
	.byte	-52
	.byte	-125
	.byte	29
	.byte	58
	.byte	116
	.byte	-24
	.byte	-53
	.byte	-115
	.byte	1
	.byte	2
	.byte	4
	.byte	8
	.byte	16
	.byte	32
	.byte	64
	.byte	-128
	.byte	27
	.byte	54
	.byte	108
	.byte	-40
	.byte	-85
	.byte	77
	.byte	-102
	.byte	47
	.byte	94
	.byte	-68
	.byte	99
	.byte	-58
	.byte	-105
	.byte	53
	.byte	106
	.byte	-44
	.byte	-77
	.byte	125
	.byte	-6
	.byte	-17
	.byte	-59
	.byte	-111
	.byte	57
	.byte	114
	.byte	-28
	.byte	-45
	.byte	-67
	.byte	97
	.byte	-62
	.byte	-97
	.byte	37
	.byte	74
	.byte	-108
	.byte	51
	.byte	102
	.byte	-52
	.byte	-125
	.byte	29
	.byte	58
	.byte	116
	.byte	-24
	.byte	-53
	.byte	-115
	.byte	1
	.byte	2
	.byte	4
	.byte	8
	.byte	16
	.byte	32
	.byte	64
	.byte	-128
	.byte	27
	.byte	54
	.byte	108
	.byte	-40
	.byte	-85
	.byte	77
	.byte	-102
	.byte	47
	.byte	94
	.byte	-68
	.byte	99
	.byte	-58
	.byte	-105
	.byte	53
	.byte	106
	.byte	-44
	.byte	-77
	.byte	125
	.byte	-6
	.byte	-17
	.byte	-59
	.byte	-111
	.byte	57
	.byte	114
	.byte	-28
	.byte	-45
	.byte	-67
	.byte	97
	.byte	-62
	.byte	-97
	.byte	37
	.byte	74
	.byte	-108
	.byte	51
	.byte	102
	.byte	-52
	.byte	-125
	.byte	29
	.byte	58
	.byte	116
	.byte	-24
	.byte	-53
	.byte	-115
	.text
	.globl	aes128_keyexpand
	.type	aes128_keyexpand, @function
aes128_keyexpand:
.LFB501:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$40, %rsp
	movdqa	%xmm0, -144(%rbp)
	movdqa	%xmm1, -160(%rbp)
	movdqa	-144(%rbp), %xmm0
	pslldq	$4, %xmm0
	movdqa	-144(%rbp), %xmm1
	movdqa	%xmm1, -16(%rbp)
	movdqa	%xmm0, -32(%rbp)
	movdqa	-32(%rbp), %xmm0
	movdqa	-16(%rbp), %xmm1
	pxor	%xmm1, %xmm0
	movdqa	%xmm0, -144(%rbp)
	movdqa	-144(%rbp), %xmm0
	pslldq	$4, %xmm0
	movdqa	-144(%rbp), %xmm1
	movdqa	%xmm1, -48(%rbp)
	movdqa	%xmm0, -64(%rbp)
	movdqa	-64(%rbp), %xmm0
	movdqa	-48(%rbp), %xmm1
	pxor	%xmm1, %xmm0
	movdqa	%xmm0, -144(%rbp)
	movdqa	-144(%rbp), %xmm0
	pslldq	$4, %xmm0
	movdqa	-144(%rbp), %xmm1
	movdqa	%xmm1, -80(%rbp)
	movdqa	%xmm0, -96(%rbp)
	movdqa	-96(%rbp), %xmm0
	movdqa	-80(%rbp), %xmm1
	pxor	%xmm1, %xmm0
	movdqa	%xmm0, -144(%rbp)
	movdqa	-160(%rbp), %xmm0
	pshufd	$255, %xmm0, %xmm0
	movdqa	%xmm0, -160(%rbp)
	movdqa	-144(%rbp), %xmm0
	movdqa	%xmm0, -112(%rbp)
	movdqa	-160(%rbp), %xmm0
	movdqa	%xmm0, -128(%rbp)
	movdqa	-128(%rbp), %xmm0
	movdqa	-112(%rbp), %xmm1
	pxor	%xmm1, %xmm0
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE501:
	.size	aes128_keyexpand, .-aes128_keyexpand
	.section	.rodata
.LC0:
	.string	"Message"
.LC1:
	.string	"Key"
.LC2:
	.string	"Crypt"
.LC3:
	.string	"Decrypted"
	.text
	.globl	main
	.type	main, @function
main:
.LFB502:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$400, %rsp
	movq	$0, -16(%rbp)
	movq	$0, -8(%rbp)
	movb	$67, -16(%rbp)
	movb	$108, -15(%rbp)
	movb	$101, -14(%rbp)
	movb	$97, -13(%rbp)
	movb	$114, -12(%rbp)
	movb	$116, -11(%rbp)
	movb	$101, -10(%rbp)
	movb	$120, -9(%rbp)
	movb	$116, -8(%rbp)
	movq	$0, -32(%rbp)
	movq	$0, -24(%rbp)
	movb	$83, -32(%rbp)
	movb	$101, -31(%rbp)
	movb	$99, -30(%rbp)
	movb	$114, -29(%rbp)
	movb	$101, -28(%rbp)
	movb	$116, -27(%rbp)
	movb	$115, -26(%rbp)
	movb	$70, -25(%rbp)
	movb	$111, -24(%rbp)
	leaq	-400(%rbp), %rdx
	leaq	-32(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	expandkey128
	leaq	-48(%rbp), %rdx
	leaq	-400(%rbp), %rcx
	leaq	-16(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	encrypt128
	leaq	-64(%rbp), %rdx
	leaq	-400(%rbp), %rcx
	leaq	-48(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	decrypt128
	leaq	-16(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC0, %edi
	call	p
	leaq	-32(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC1, %edi
	call	p
	leaq	-48(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC2, %edi
	call	p
	leaq	-64(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC3, %edi
	call	p
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE502:
	.size	main, .-main
	.section	.rodata
.LC4:
	.string	"%s: %s\n"
	.text
	.globl	p
	.type	p, @function
p:
.LFB503:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movq	%rdi, -40(%rbp)
	movq	%rsi, -48(%rbp)
	movq	-48(%rbp), %rcx
	leaq	-32(%rbp), %rax
	movl	$16, %edx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	memcpy
	movb	$0, -16(%rbp)
	leaq	-32(%rbp), %rdx
	movq	-40(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC4, %edi
	movl	$0, %eax
	call	printf
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE503:
	.size	p, .-p
	.globl	expandkey128
	.type	expandkey128, @function
expandkey128:
.LFB504:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$184, %rsp
	.cfi_offset 3, -24
	movq	%rdi, -184(%rbp)
	movq	%rsi, -192(%rbp)
	movq	-184(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movdqa	(%rax), %xmm0
	movq	-192(%rbp), %rax
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	leaq	16(%rax), %rbx
	movq	-192(%rbp), %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$1, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	32(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$16, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$2, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$16, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	48(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$32, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$4, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$32, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	64(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$48, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$8, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$48, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	80(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$64, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$16, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$64, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	96(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$80, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$32, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$80, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	112(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$96, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$64, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$96, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	128(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$112, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$128, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$112, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	144(%rax), %rbx
	movq	-192(%rbp), %rax
	subq	$-128, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$27, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	subq	$-128, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	leaq	160(%rax), %rbx
	movq	-192(%rbp), %rax
	addq	$144, %rax
	movdqa	(%rax), %xmm0
	aeskeygenassist	$54, %xmm0, %xmm1
	movq	-192(%rbp), %rax
	addq	$144, %rax
	movdqa	(%rax), %xmm0
	call	aes128_keyexpand
	movdqa	%xmm0, (%rbx)
	movq	-192(%rbp), %rax
	addq	$176, %rax
	movq	-192(%rbp), %rdx
	addq	$144, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -48(%rbp)
	aesimc	-48(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$192, %rax
	movq	-192(%rbp), %rdx
	subq	$-128, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -64(%rbp)
	aesimc	-64(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$208, %rax
	movq	-192(%rbp), %rdx
	addq	$112, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -80(%rbp)
	aesimc	-80(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$224, %rax
	movq	-192(%rbp), %rdx
	addq	$96, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -96(%rbp)
	aesimc	-96(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$240, %rax
	movq	-192(%rbp), %rdx
	addq	$80, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -112(%rbp)
	aesimc	-112(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$256, %rax
	movq	-192(%rbp), %rdx
	addq	$64, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -128(%rbp)
	aesimc	-128(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$272, %rax
	movq	-192(%rbp), %rdx
	addq	$48, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -144(%rbp)
	aesimc	-144(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$288, %rax
	movq	-192(%rbp), %rdx
	addq	$32, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -160(%rbp)
	aesimc	-160(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	addq	$304, %rax
	movq	-192(%rbp), %rdx
	addq	$16, %rdx
	movdqa	(%rdx), %xmm0
	movdqa	%xmm0, -176(%rbp)
	aesimc	-176(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	movq	-192(%rbp), %rax
	leaq	320(%rax), %rdx
	movq	-192(%rbp), %rax
	movdqa	(%rax), %xmm0
	movdqa	%xmm0, (%rdx)
	addq	$184, %rsp
	popq	%rbx
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE504:
	.size	expandkey128, .-expandkey128
	.globl	encrypt128
	.type	encrypt128, @function
encrypt128:
.LFB505:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$320, %rsp
	movq	%rdi, -424(%rbp)
	movq	%rsi, -432(%rbp)
	movq	%rdx, -440(%rbp)
	movq	-424(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movdqa	(%rax), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -48(%rbp)
	movdqa	%xmm0, -64(%rbp)
	movdqa	-64(%rbp), %xmm0
	movdqa	-48(%rbp), %xmm1
	pxor	%xmm1, %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$16, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -80(%rbp)
	movdqa	%xmm0, -96(%rbp)
	movdqa	-80(%rbp), %xmm0
	aesenc	-96(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$32, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -112(%rbp)
	movdqa	%xmm0, -128(%rbp)
	movdqa	-112(%rbp), %xmm0
	aesenc	-128(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$48, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -144(%rbp)
	movdqa	%xmm0, -160(%rbp)
	movdqa	-144(%rbp), %xmm0
	aesenc	-160(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$64, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -176(%rbp)
	movdqa	%xmm0, -192(%rbp)
	movdqa	-176(%rbp), %xmm0
	aesenc	-192(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$80, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -208(%rbp)
	movdqa	%xmm0, -224(%rbp)
	movdqa	-208(%rbp), %xmm0
	aesenc	-224(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$96, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -240(%rbp)
	movdqa	%xmm0, -256(%rbp)
	movdqa	-240(%rbp), %xmm0
	aesenc	-256(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$112, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -272(%rbp)
	movdqa	%xmm0, -288(%rbp)
	movdqa	-272(%rbp), %xmm0
	aesenc	-288(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	subq	$-128, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -304(%rbp)
	movdqa	%xmm0, -320(%rbp)
	movdqa	-304(%rbp), %xmm0
	aesenc	-320(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$144, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -336(%rbp)
	movdqa	%xmm0, -352(%rbp)
	movdqa	-336(%rbp), %xmm0
	aesenc	-352(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$160, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -368(%rbp)
	movdqa	%xmm0, -384(%rbp)
	movdqa	-368(%rbp), %xmm0
	aesenclast	-384(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-440(%rbp), %rax
	movq	%rax, -392(%rbp)
	movdqa	-16(%rbp), %xmm0
	movdqa	%xmm0, -416(%rbp)
	movq	-392(%rbp), %rax
	movdqa	-416(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE505:
	.size	encrypt128, .-encrypt128
	.globl	decrypt128
	.type	decrypt128, @function
decrypt128:
.LFB506:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$320, %rsp
	movq	%rdi, -424(%rbp)
	movq	%rsi, -432(%rbp)
	movq	%rdx, -440(%rbp)
	movq	-424(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movdqa	(%rax), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$160, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -48(%rbp)
	movdqa	%xmm0, -64(%rbp)
	movdqa	-64(%rbp), %xmm0
	movdqa	-48(%rbp), %xmm1
	pxor	%xmm1, %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$176, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -80(%rbp)
	movdqa	%xmm0, -96(%rbp)
	movdqa	-80(%rbp), %xmm0
	aesdec	-96(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$192, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -112(%rbp)
	movdqa	%xmm0, -128(%rbp)
	movdqa	-112(%rbp), %xmm0
	aesdec	-128(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$208, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -144(%rbp)
	movdqa	%xmm0, -160(%rbp)
	movdqa	-144(%rbp), %xmm0
	aesdec	-160(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$224, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -176(%rbp)
	movdqa	%xmm0, -192(%rbp)
	movdqa	-176(%rbp), %xmm0
	aesdec	-192(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$240, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -208(%rbp)
	movdqa	%xmm0, -224(%rbp)
	movdqa	-208(%rbp), %xmm0
	aesdec	-224(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$256, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -240(%rbp)
	movdqa	%xmm0, -256(%rbp)
	movdqa	-240(%rbp), %xmm0
	aesdec	-256(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$272, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -272(%rbp)
	movdqa	%xmm0, -288(%rbp)
	movdqa	-272(%rbp), %xmm0
	aesdec	-288(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$288, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -304(%rbp)
	movdqa	%xmm0, -320(%rbp)
	movdqa	-304(%rbp), %xmm0
	aesdec	-320(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$304, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -336(%rbp)
	movdqa	%xmm0, -352(%rbp)
	movdqa	-336(%rbp), %xmm0
	aesdec	-352(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-432(%rbp), %rax
	addq	$320, %rax
	movdqa	(%rax), %xmm0
	movdqa	-16(%rbp), %xmm1
	movdqa	%xmm1, -368(%rbp)
	movdqa	%xmm0, -384(%rbp)
	movdqa	-368(%rbp), %xmm0
	aesdeclast	-384(%rbp), %xmm0
	movdqa	%xmm0, -16(%rbp)
	movq	-440(%rbp), %rax
	movq	%rax, -392(%rbp)
	movdqa	-16(%rbp), %xmm0
	movdqa	%xmm0, -416(%rbp)
	movq	-392(%rbp), %rax
	movdqa	-416(%rbp), %xmm0
	movdqa	%xmm0, (%rax)
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE506:
	.size	decrypt128, .-decrypt128
	.ident	"GCC: (Debian 4.8.2-8) 4.8.2"
	.section	.note.GNU-stack,"",@progbits
