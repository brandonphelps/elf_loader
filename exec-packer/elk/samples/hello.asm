	;;  in `hello.asm`

	global _start

	section .text


	;; we are going to call the sys_write function
	;; takes in 3 arguments,
	;; fd, char* and size
	;; https://filippo.io/linux-syscall-table/
	;; indicates that sys_write i %rax 1, so a
	;; 1 is placed into rax 1
	;; next is x64_64 call convension
	;; https://en.wikipedia.org/wiki/X86_calling_conventions
	;; indicates that to pass parameters we must
	;; use rdi, rsi, rdx, rcx, r8, r9 for arguments
	;;  sys_write is of (unsigned int fd, char* msg, size_t count)
	;; so  we use rdi of 1 so its fd is equal to stdout	
	;; rsi is then address of msg
	;; rdx is then size including null
_start:	mov rdi, 1     		; stdout fd 
	mov rsi, msg 		; 
	mov rdx, 9		; 8 chars + newline
	mov rax, 1 		; write syscall
	syscall

	mov rdi, 1
	mov rsi, msg2
	mov rdx, 12
	mov rax, 1
	syscall
	
	;; syscall for sys_exit
	;; so rax should be 60
	xor rdi, rdi		; return 0
	mov rax, 60 		; exit syscall

	syscall

	section .data
msg:	db "hi there", 10
msg2:	dw "wakka wakka"

