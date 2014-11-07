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

int main(void)
{
  int   fd;
  char  buff[260] = {0};

  fd = open("serial.txt", O_RDONLY);
  read(fd, buff, 256);
  close(fd);

  if (buff[0] != 'a')
    return 1;

  if (buff[1] != 'b')
    return 1;

  if (buff[2] != 'c')
    return 1;

  printf("Good boy\n");

  return 0;
}
