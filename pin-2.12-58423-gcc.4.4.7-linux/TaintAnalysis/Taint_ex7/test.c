
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

void foo(char *buf)
{
  printf(buf);
}

int main(int ac, char **av)
{
  int  fd;
  char *buf;

  if (!(buf = malloc(32)))
    return -1;
  
  fd = open("./file.txt", O_RDONLY);
  read(fd, buf, 32);
  close(fd);

  foo(buf);
}
