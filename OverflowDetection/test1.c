/*
**  Jonathan Salwan - 2013-10-12
** 
**  http://shell-storm.org
**  http://twitter.com/JonathanSalwan
** 
**  This program is free software: you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software  Foundation, either  version 3 of  the License, or
**  (at your option) any later version.
*/

void foo(void)
{
  int a, b, i;

  a = 0x90909090;
  b = 0x91919191;

  for (i = 0; i <= sizeof(b); i++) /* off-by-one */
    *(((unsigned char *)(&b))+i) = 'E';
  
}

int main(int ac, const char *av[])
{
  foo();
}
