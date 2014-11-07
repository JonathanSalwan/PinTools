
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define true 0
#define false !true

int foo(char *buf)
{
  if (buf[0] != 'A')
    return false;
  if (buf[1] != 'B')
    return false;
  if (buf[2] != 'C')
    return false;
  if (buf[3] != 'D')
    return false;
  return true;
}

int main(int ac, char **av)
{
  int fd;
  char *buf;

  if (!(buf = malloc(32)))
    return -1;

  fd = open("./file.txt", O_RDONLY);
  read(fd, buf, 32), close(fd);
  foo(buf);
}
