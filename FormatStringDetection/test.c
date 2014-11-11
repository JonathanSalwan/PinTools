
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

void foo(char *buf)
{
  unsigned int i;
  char *ptr;

  if (!(ptr = malloc(8)))
    return;

  for (i = 0; i < 8; i++)
    ptr[i] = buf[i]; /* spread the taint to another area */

  printf(ptr);       /* warn format string */
}

int main(int ac, char **av)
{
  int  fd;
  char *buf;

  if (!(buf = malloc(8)))
    return -1;
  
  fd = open("./file.txt", O_RDONLY);
  read(fd, buf, 8); /* The range [buff, buff+32] is tainted */
  close(fd);

  foo(buf); 
}

