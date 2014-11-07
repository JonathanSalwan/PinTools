//
//  Jonathan Salwan - Copyright (C) 2013-08
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

class Test
{
  private:
    int a;
    void foo(void);

  public:
    Test(int num) { this->a = num; };
    ~Test() {};
    void wrapper(void);
};

void Test::foo(void)
{
  std::cout << this->a << std::endl;
}

void Test::wrapper(void)
{
  this->foo();
}

int main()
{
  Test *ptr = new Test(1234);
  Test *old = ptr;

  ptr->wrapper();
  delete ptr;
  ptr->wrapper();
  ptr = new Test(4321);
  old->wrapper();
}
