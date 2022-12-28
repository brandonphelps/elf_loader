asm-hello.out: asm-hello/hello.o
	ld asm-hello/hello.o -o $@

# linux
asm-hello/hello.o: asm-hello/hello.asm
	nasm -g -felf64 $< -o $@

# mac
#       nasm -fmaco64 hello.asm -> hello.o
