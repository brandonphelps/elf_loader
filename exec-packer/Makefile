

clean_targets := 

define ASM_BUILD
elk/samples/$1.o: elk/samples/$1.asm
	nasm -g -felf64 $$< -o $$@

clean_targets += elk/samples/$1.o
endef

define ASM_LINK
$1: $2
	ld --dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie $$^ -o $$@
clean_targets += $1
all: $1
endef

all: hello nodata entry_point hello-pie hello-dl

nodata: elk/samples/nodata.o
	ld elk/samples/nodata.o -o $@

hello: elk/samples/hello.o
	ld elk/samples/hello.o -o $@

$(eval $(call ASM_BUILD,hello-ld))
$(eval $(call ASM_BUILD,hello))
$(eval $(call ASM_BUILD,hello-pie))
$(eval $(call ASM_BUILD,msg))
$(eval $(call ASM_LINK,hello-ld,elk/samples/hello-ld.o elk/samples/msg.o))


libmsg.so: elk/samples/msg.o
	ld -shared elk/samples/msg.o -o libmsg.so

hello-dl: libmsg.so elk/samples/hello-ld.o
	ld -rpath "." -rpath-link "$$ORIGIN" -pie --dynamic-linker /lib64/ld-linux-x86-64.so.2 elk/samples/hello-ld.o libmsg.so -o hello-dl

hello-pie: elk/samples/hello-pie.o
	ld --dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie $< -o $@

elk/samples/nodata.o: elk/samples/nodata.asm
	nasm -g -felf64 $< -o $@

entry_point: elk/samples/entry_point.c
	gcc -g $< -o $@


clean:
	rm -rf $(clean_targets)

# mac
#       nasm -fmaco64 hello.asm -> hello.o
