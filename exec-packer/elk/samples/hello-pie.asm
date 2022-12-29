
	global _start

	section .text

_start:	mov rdi, 1 		; stdout fd
	lea rsi, [rel msg]
	mov rdx, 9
	mov rax, 1
	syscall

	xor rdi, rdi		; return code 0
	mov rax, 60 		; exit syscall
	syscall
	
	section .data

msg:	db "hi there", 10
