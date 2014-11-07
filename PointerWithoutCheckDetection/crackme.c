/*
**  Jonathan Salwan - Copyright (C) 2013-07
** 
**  http://twitter.com/JonathanSalwan
**  http://shell-storm.org
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
  char *buf;
  char *r;

  buf = malloc(256);
  if (!buf)
    return -1;
  r = buf;
  fd = open("serial.txt", O_RDONLY);
  read(fd, buf, 256);
  close(fd);
  while (i < 5){
    if ((*buf ^ 0x55) != *serial)
      return 0;
    buf++, serial++, i++;
  }
  if (!*buf)
    printf("Good boy\n");
  free(r);
  return 0;
}
