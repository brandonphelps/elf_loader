

all: hello nodata entry_point

hello: elk/samples/hello.o
	ld elk/samples/hello.o -o $@

nodata: elk/samples/nodata.o
	ld elk/samples/nodata.o -o $@

# linux
elk/samples/hello.o: elk/samples/hello.asm
	nasm -g -felf64 $< -o $@

elk/samples/nodata.o: elk/samples/nodata.asm
	nasm -g -felf64 $< -o $@

entry_point: elk/samples/entry_point.c
	gcc -g $< -o $@




# mac
#       nasm -fmaco64 hello.asm -> hello.o
