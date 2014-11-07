
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define true 0
#define false !true

char *foo2(char *buf)
{
  char d = buf[0];
  return &d;
}

int foo1(char *buf)
{
  *foo2(buf) = 1; /* UAF match          */
}

int main(int ac, char **av)
{
  int fd;
  char *buf;

  if (!(buf = malloc(32)))
    return -1;

  fd = open("./file.txt", O_RDONLY);
  read(fd, buf, 32), close(fd);
  foo1(buf);
}
