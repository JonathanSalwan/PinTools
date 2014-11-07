
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

void foo(char *buf)
{
  if (buf[0] != 'a')
    return ;
  if (buf[1] != 'b')
    return ;
  if (buf[2] != 'c')
    return ;
  if (buf[3] != 'd')
    return ;
  if (buf[4] != 'e')
    return ;

  printf("Good boy\n");
}

char *test_stack_frame;

void pre_foo(void)
{
  int fd;
  
  char buf[256]; /* Taint on the stack - Stack Frame Test */
  
  test_stack_frame = buf;

  fd = open("./serial.txt", O_RDONLY);
  read(fd, buf, 256);
  close(fd);

  foo(buf);
}

int main(int ac, char **av)
{
  char test;

  pre_foo();
  test = test_stack_frame[0]; /* 'test' should not be tainted ! */
}
