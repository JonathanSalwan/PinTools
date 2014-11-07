//
//  Jonathan Salwan - 2013-09-09
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
// 
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software  Foundation, either  version 3 of  the License, or
//  (at your option) any later version.
//

#include <iostream>

#define CONST_SIZE 32

class Test
{
  private:
    char *_buffer;

  
  public:

    Test(){
      this->_buffer = new char[CONST_SIZE];
    };

    ~Test(){
      delete [] this->_buffer;
    };

    void fillBuffer(void){
      unsigned int i;
  
      for (i = 0; i <= CONST_SIZE; i++) /* off-by-one */
        this->_buffer[i] = 'A';
    };
};

int main(int ac, const char *av[])
{
  Test test;

  test.fillBuffer();

  return 0;
}

