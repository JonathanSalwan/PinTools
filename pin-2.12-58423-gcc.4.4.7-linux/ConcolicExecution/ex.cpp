//
//  Jonathan Salwan - 2013-08-24
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
#include "z3++.h"

//class SolveEq
//{
//  private:
//    z3::context *c;
//    z3::solver  *s;
//    z3::expr    *eq;
//    z3::model   *m;
//    z3::expr    *x;
//
//  public:
//    SolveEq();
//    ~SolveEq();
//};
//
//SolveEq::SolveEq()
//{
//  this->c  = new z3::context;
//  this->x  = new z3::expr(c->bv_const("x", 32));
//  this->s  = new z3::solver(*(this->c));
//  this->eq = new z3::expr(*(this->x));
//};
//
//SolveEq::~SolveEq()
//{
//  delete this->c;
//  delete this->x;
//  delete this->s;
//  delete this->eq;
//}
//
//SolveEq::setExpr(z3::expr &expr)
//{
//  *(this->eq) = expr;
//}

int main(int ac, const char *av[])
{
  z3::context *c;
  z3::expr    *x;
  z3::solver  *s;
  z3::expr    *eq;
  z3::model   *m;

  c  = new z3::context;
  x  = new z3::expr(c->bv_const("x", 32));
  s  = new z3::solver(*c);
  eq = new z3::expr(*x);

  *eq = (*x ^ 0x55);
  *eq = (*eq == 0x30);

  s->add(*eq);

  std::cout << s->check() << "\n";
  m = new z3::model(s->get_model());
  std::cout << *m << "\n";

  delete m;
  delete eq;
  delete x;
  delete s;
  delete c;

// ----------------------------

  c  = new z3::context;
  x  = new z3::expr(c->bv_const("x", 32));
  s  = new z3::solver(*c);
  eq = new z3::expr(*x);

  *eq = (*x ^ 0x55);
  *eq = (*eq == 0x39);

  s->add(*eq);

  std::cout << s->check() << "\n";
  m = new z3::model(s->get_model());
  std::cout << *m << "\n";

  delete m;
  delete eq;
  delete x;
  delete s;
  delete c;

  return 0;
}

