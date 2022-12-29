
#include <stdio.h>
#include <stdlib.h>

const int cons = 29;

const char* instructions = "\x48\x31\xFF\xB8\x3C\x00\x00\x0F\x05";

int main() {
  printf("        main @ %p\n", &main);
  printf("instructions @ %p\n", instructions);
  void (*f)(void) = (void*)instructions;
  printf("jumping...\n");

  // use gdb and info proc to get pid
  // then use pmap to get process memory table.
  f();
  printf("after jump\b");
}
