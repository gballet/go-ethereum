/*
 * Entry point for keeper on ZisK. Sets up the machine state that the Go
 * runtime expects from OpenBSD's crt0: a stack holding argc, argv, envp and
 * auxv, then calls main(argc, argv), which Go defines to enter rt0_go.
 */

	.section .text.init, "ax", @progbits
	.globl _start
_start:
	.option push
	.option norelax
	la	gp, __global_pointer$
	.option pop
	la	sp, _init_stack_top
	la	tp, __zisk_tls
	addi	sp, sp, -64
	mv	a0, sp
	call	__zisk_boot_frame
	ld	a0, 0(sp)
	addi	a1, sp, 8
	j	main
