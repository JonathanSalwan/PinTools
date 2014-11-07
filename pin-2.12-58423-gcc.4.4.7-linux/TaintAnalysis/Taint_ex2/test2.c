
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define true 0
#define false !true

int foo(char *buf)
{
  if (buf[0] != 't')
    return false;
  if (buf[0] != 'e')
    return false;
  if (buf[0] != 's')
    return false;
  if (buf[0] != 't')
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
