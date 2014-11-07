/*
**  Jonathan Salwan - 2013-08-22
** 
**  http://shell-storm.org
**  http://twitter.com/JonathanSalwan
** 
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software  Foundation, either  version 3 of  the License, or
**  (at your option) any later version.
*/

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>

char *serial = "\x30\x39\x3c\x21\x30";

int main(void)
{
  int fd, i = 0;
  char buf[260] = {0};
  char *r = buf;

  fd = open("serial.txt", O_RDONLY);
  read(fd, r, 256);
  close(fd);

  if ((buf[0] ^ 0x55) + 1 == 'A')
    printf("Good boy\n");

  return 0;
}
