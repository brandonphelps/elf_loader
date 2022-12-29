all: asm-hello.out elk/samples/entry_point

asm-hello.out: asm-hello/hello.o
	ld asm-hello/hello.o -o $@

# linux
asm-hello/hello.o: asm-hello/hello.asm
	nasm -g -felf64 $< -o $@

elk/samples/entry_point: elk/samples/entry_point.c
	gcc -g $< -o $@


# mac
#       nasm -fmaco64 hello.asm -> hello.o
