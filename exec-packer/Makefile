

all: hello nodata entry_point hello-pie

nodata: elk/samples/nodata.o
	ld elk/samples/nodata.o -o $@

hello: elk/samples/hello.o
	ld elk/samples/hello.o -o $@


# linux
elk/samples/hello.o: elk/samples/hello.asm
	nasm -g -felf64 $< -o $@

hello-pie: elk/samples/hello-pie.o
	ld --dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie elk/samples/hello-pie.o -o $@

# linux
elk/samples/hello-pie.o: elk/samples/hello-pie.asm
	nasm -g -felf64 $< -o $@

elk/samples/nodata.o: elk/samples/nodata.asm
	nasm -g -felf64 $< -o $@

entry_point: elk/samples/entry_point.c
	gcc -g $< -o $@




# mac
#       nasm -fmaco64 hello.asm -> hello.o
