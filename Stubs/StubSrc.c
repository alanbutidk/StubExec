#include <stdio.h>

#pragma section(".data", read, write)
__declspec(allocate(".data"))
char injected_message[256] = "StubExec says hi!";

int main() {
  printf("\n%s\n", injected_message);
  return 0;
}