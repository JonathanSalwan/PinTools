
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int ac, char **av)
{
  char c, *buf;

  buf = malloc(32);
  c = buf[0];
  printf("%x\n", c);
}
