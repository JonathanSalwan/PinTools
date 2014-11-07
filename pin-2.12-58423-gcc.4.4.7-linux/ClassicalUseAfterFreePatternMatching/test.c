
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define true 0
#define false !true

int main(int ac, char **av)
{
  int fd;
  char *buf;
  char c;

  if (!(buf = malloc(32)))
    return -1;

  c = buf[0];
  free(buf);
  c = buf[0];
  buf = malloc(32);
  c = buf[0];
}
