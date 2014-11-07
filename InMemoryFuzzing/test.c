/*
**  Jonathan Salwan - 2013-08-14
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

int foo(int i, char *tab)
{ 
  if (i > 0 && i < 0x3000){
    printf("%c\n", tab[i]);
    return 0;
  }
  return -1;
}

int main(int ac, const char *av[])
{
  char tab[] = "qwertyuiopasdfghjklzxcvbnm1234567890";
  
  if (ac == 2)
    foo(atoi(av[1]), tab);
  
  return 0;
}
