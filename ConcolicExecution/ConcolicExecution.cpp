//
//  BEGIN_LEGAL 
//  Intel Open Source License 
//
//  Copyright (c) 2002-2013 Intel Corporation. All rights reserved.
// 
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//  Redistributions of source code must retain the above copyright notice,
//  this list of conditions and the following disclaimer.  Redistributions
//  in binary form must reproduce the above copyright notice, this list of
//  conditions and the following disclaimer in the documentation and/or
//  other materials provided with the distribution.  Neither the name of
//  the Intel Corporation nor the names of its contributors may be used to
//  endorse or promote products derived from this software without
//  specific prior written permission.
//  
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
//  ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//  END_LEGAL
//
//  ------------------------------------------------------------------------
//
//  Jonathan Salwan - 2013-08-17
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Concolic execution with Pin
//

#include "pin.H"
#include "z3++.h"
#include <asm/unistd.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <sstream>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

std::list<UINT64> addressTainted;
std::list<REG> regsTainted;

KNOB<std::string>  KnobTaintFile(KNOB_MODE_WRITEONCE, "pintool", "taint-file", "none", "Taint file name");

static UINT64 targetedFd;
static UINT64 flag;
static UINT64 uniqueID;

std::list< std::pair<UINT64, std::string> > constraintList;

z3::context   *z3Context;
z3::expr      *z3Var;
z3::solver    *z3Solver;
z3::expr      *z3Equation;
z3::model     *z3Model;

static char goodSerial[32] = {0};
static unsigned int offsetSerial;

#define ID_RAX 0
#define ID_RBX 1
#define ID_RCX 2
#define ID_RDX 3
#define ID_RDI 4
#define ID_RSI 5

static UINT64 regID[] = {
    (UINT64)-1, /* ID_RAX */
    (UINT64)-1, /* ID_RBX */
    (UINT64)-1, /* ID_RCX */
    (UINT64)-1, /* ID_RDX */
    (UINT64)-1, /* ID_RDI */
    (UINT64)-1  /* ID_RSI */
};

INT32 Usage()
{
    cerr << "Concolic execution" << endl;
    return -1;
}

bool checkAlreadyRegTainted(REG reg)
{
  list<REG>::iterator i;

  for(i = regsTainted.begin(); i != regsTainted.end(); i++){
    if (*i == reg){
      return true;
    }
  }
  return false;
}

VOID removeMemTainted(UINT64 addr)
{
  addressTainted.remove(addr);
  std::cout << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
}

VOID addMemTainted(UINT64 addr)
{
  addressTainted.push_back(addr);
  std::cout << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;
}

bool taintReg(REG reg)
{
  if (checkAlreadyRegTainted(reg) == true){
    std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
    return false;
  }

  switch(reg){

    case REG_RAX:  regsTainted.push_front(REG_RAX);
    case REG_EAX:  regsTainted.push_front(REG_EAX); 
    case REG_AX:   regsTainted.push_front(REG_AX); 
    case REG_AH:   regsTainted.push_front(REG_AH); 
    case REG_AL:   regsTainted.push_front(REG_AL); 
         break;

    case REG_RBX:  regsTainted.push_front(REG_RBX);
    case REG_EBX:  regsTainted.push_front(REG_EBX);
    case REG_BX:   regsTainted.push_front(REG_BX);
    case REG_BH:   regsTainted.push_front(REG_BH);
    case REG_BL:   regsTainted.push_front(REG_BL);
         break;

    case REG_RCX:  regsTainted.push_front(REG_RCX); 
    case REG_ECX:  regsTainted.push_front(REG_ECX);
    case REG_CX:   regsTainted.push_front(REG_CX);
    case REG_CH:   regsTainted.push_front(REG_CH);
    case REG_CL:   regsTainted.push_front(REG_CL);
         break;

    case REG_RDX:  regsTainted.push_front(REG_RDX); 
    case REG_EDX:  regsTainted.push_front(REG_EDX); 
    case REG_DX:   regsTainted.push_front(REG_DX); 
    case REG_DH:   regsTainted.push_front(REG_DH); 
    case REG_DL:   regsTainted.push_front(REG_DL); 
         break;

    case REG_RDI:  regsTainted.push_front(REG_RDI); 
    case REG_EDI:  regsTainted.push_front(REG_EDI); 
    case REG_DI:   regsTainted.push_front(REG_DI); 
    case REG_DIL:  regsTainted.push_front(REG_DIL); 
         break;

    case REG_RSI:  regsTainted.push_front(REG_RSI); 
    case REG_ESI:  regsTainted.push_front(REG_ESI); 
    case REG_SI:   regsTainted.push_front(REG_SI); 
    case REG_SIL:  regsTainted.push_front(REG_SIL); 
         break;

    default:
      std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
      return false;
  }
  std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
  return true;
}

bool removeRegTainted(REG reg)
{
  switch(reg){

    case REG_RAX:  regsTainted.remove(REG_RAX);
    case REG_EAX:  regsTainted.remove(REG_EAX);
    case REG_AX:   regsTainted.remove(REG_AX);
    case REG_AH:   regsTainted.remove(REG_AH);
    case REG_AL:   regsTainted.remove(REG_AL);
         break;

    case REG_RBX:  regsTainted.remove(REG_RBX);
    case REG_EBX:  regsTainted.remove(REG_EBX);
    case REG_BX:   regsTainted.remove(REG_BX);
    case REG_BH:   regsTainted.remove(REG_BH);
    case REG_BL:   regsTainted.remove(REG_BL);
         break;

    case REG_RCX:  regsTainted.remove(REG_RCX); 
    case REG_ECX:  regsTainted.remove(REG_ECX);
    case REG_CX:   regsTainted.remove(REG_CX);
    case REG_CH:   regsTainted.remove(REG_CH);
    case REG_CL:   regsTainted.remove(REG_CL);
         break;

    case REG_RDX:  regsTainted.remove(REG_RDX); 
    case REG_EDX:  regsTainted.remove(REG_EDX); 
    case REG_DX:   regsTainted.remove(REG_DX); 
    case REG_DH:   regsTainted.remove(REG_DH); 
    case REG_DL:   regsTainted.remove(REG_DL); 
         break;

    case REG_RDI:  regsTainted.remove(REG_RDI); 
    case REG_EDI:  regsTainted.remove(REG_EDI); 
    case REG_DI:   regsTainted.remove(REG_DI); 
    case REG_DIL:  regsTainted.remove(REG_DIL); 
         break;

    case REG_RSI:  regsTainted.remove(REG_RSI); 
    case REG_ESI:  regsTainted.remove(REG_ESI); 
    case REG_SI:   regsTainted.remove(REG_SI); 
    case REG_SIL:  regsTainted.remove(REG_SIL); 
         break;

    default:
      return false;
  }
  std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
  return true;
}

UINT64 getRegID(REG reg)
{
  switch(reg){
    case REG_RAX:  
    case REG_EAX:  
    case REG_AX:   
    case REG_AH:   
    case REG_AL:  
         return regID[ID_RAX];  

    case REG_RBX:  
    case REG_EBX:  
    case REG_BX:   
    case REG_BH:   
    case REG_BL:   
         return regID[ID_RBX];  

    case REG_RCX:  
    case REG_ECX:  
    case REG_CX:   
    case REG_CH:   
    case REG_CL:   
         return regID[ID_RCX];  

    case REG_RDX:  
    case REG_EDX:  
    case REG_DX:   
    case REG_DH:   
    case REG_DL:   
         return regID[ID_RDX];  

    case REG_RDI:  
    case REG_EDI:  
    case REG_DI:   
    case REG_DIL:  
         return regID[ID_RDI];  

    case REG_RSI:  
    case REG_ESI:  
    case REG_SI:   
    case REG_SIL:  
         return regID[ID_RSI];  

    default:
      return -1;
  }
}

VOID setRegID(REG reg, UINT64 id)
{
  switch(reg){
    case REG_RAX:  
    case REG_EAX:  
    case REG_AX:   
    case REG_AH:   
    case REG_AL:  
         regID[ID_RAX] = id;  
         break;

    case REG_RBX:  
    case REG_EBX:  
    case REG_BX:   
    case REG_BH:   
    case REG_BL:   
         regID[ID_RBX] = id;  
         break;

    case REG_RCX:  
    case REG_ECX:  
    case REG_CX:   
    case REG_CH:   
    case REG_CL:   
         regID[ID_RCX] = id;  
         break;

    case REG_RDX:  
    case REG_EDX:  
    case REG_DX:   
    case REG_DH:   
    case REG_DL:   
         regID[ID_RDX] = id;  
         break;

    case REG_RDI:  
    case REG_EDI:  
    case REG_DI:   
    case REG_DIL:  
         regID[ID_RDI] = id;  
         break;

    case REG_RSI:  
    case REG_ESI:  
    case REG_SI:   
    case REG_SIL:  
         regID[ID_RSI] = id;  
         break;

    default:
      break;
  }
}

REG getHighReg(REG reg)
{
  switch(reg){
    case REG_RAX:  
    case REG_EAX:  
    case REG_AX:   
    case REG_AH:   
    case REG_AL:  
         return REG_RAX;

    case REG_RBX:  
    case REG_EBX:  
    case REG_BX:   
    case REG_BH:   
    case REG_BL:   
         return REG_RBX;

    case REG_RCX:  
    case REG_ECX:  
    case REG_CX:   
    case REG_CH:   
    case REG_CL:   
         return REG_RCX;

    case REG_RDX:  
    case REG_EDX:  
    case REG_DX:   
    case REG_DH:   
    case REG_DL:   
         return REG_RDX;

    case REG_RDI:  
    case REG_EDI:  
    case REG_DI:   
    case REG_DIL:  
         return REG_RDI;

    case REG_RSI:  
    case REG_ESI:  
    case REG_SI:   
    case REG_SIL:  
         return REG_RSI;

    default:
      return REG_AL; /* hack exception */
  }
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
  list<UINT64>::iterator i;
  UINT64 addr = memOp;
  std::stringstream stream;
  
  if (opCount != 2)
    return;
  
  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        std::cout << "[Constraint]\t\t" << "#" << std::dec << uniqueID << " = 0x" << std::hex << std::setfill('0') << std::setw(2) 
          << static_cast<UINT64>(*(reinterpret_cast<char *>(addr))) << std::endl;
        //stream << "0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<UINT64>(*(reinterpret_cast<char *>(addr)));
        stream << "x";
        constraintList.push_back(make_pair(uniqueID, stream.str()));
        taintReg(reg_r);
        setRegID(reg_r, uniqueID++);

        /* Construct the z3 equation */
        z3Context   = new z3::context;
        z3Var       = new z3::expr(z3Context->bv_const("x", 32));
        z3Solver    = new z3::solver(*z3Context);
        z3Equation  = new z3::expr(*z3Var);

        return ;
      }
  }
  /* if mem != tained and reg == taint => free the reg */
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
    removeRegTainted(reg_r);
    setRegID(reg_r, -1);
  }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
  list<UINT64>::iterator i;
  UINT64 addr = memOp;

  if (opCount != 2)
    return;
  
  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
          removeMemTainted(addr);
        return ;
      }
  }
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
    addMemTainted(addr);
  }
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
  if (opCount != 2)
    return;

  if (REG_valid(reg_w)){
    if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
      removeRegTainted(reg_w);
      setRegID(reg_w, -1);
    }
    else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
      //std::cout << "[Constraint]\t\t" << "#" << uniqueID << " = #" << getRegID(reg_r) << std::endl;
      taintReg(reg_w);
      //setRegID(reg_w, uniqueID++);
    }
  }
}

VOID followData(UINT64 insAddr, std::string insDis, REG reg_r)
{
  if (!REG_valid(reg_r))
    return;

  if (checkAlreadyRegTainted(reg_r)){
      std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
  }
}

BOOL replaceEq(std::string &str, const std::string &from, const std::string &to)
{
  size_t start_pos = str.find(from);
  if(start_pos == std::string::npos)
      return false;
  str.replace(start_pos, from.length(), to);
  return true;
}

std::string getRegEq(UINT64 ID)
{
  std::list< std::pair<UINT64, std::string> >::iterator i;

  for(i = constraintList.begin(); i != constraintList.end(); i++){
    if (i->first == ID){
      return i->second;
    }
  }
  return "#" + ID;
}

std::string getFullEquation(std::string eq)
{
  UINT64 i;
  std::stringstream stream;

  while (eq.find("#") != std::string::npos){
    for (i = constraintList.size(); i != 0xffffffffffffffff; i--){
      stream << "#" << i;
      replaceEq(eq, stream.str(), getRegEq(i));
      stream.clear(); stream.str("");
    }
  }

  return eq;
}

VOID xorRegReg(REG reg0, REG reg1)
{
  std::stringstream stream;

  if (checkAlreadyRegTainted(reg0) || checkAlreadyRegTainted(reg1)){
    std::cout << "[Constraint]\t\t" << "#" << std::dec << uniqueID << " = xor(#" << getRegID(reg0) << ", #" << getRegID(reg1) << ")" << std::endl;
    stream << "xor(#" << getRegID(reg0) << ", #" << getRegID(reg1) << ")";
    constraintList.push_back(make_pair(uniqueID, stream.str()));
    setRegID(reg0,  uniqueID++);
  }
}

VOID xorRegImm(REG reg, UINT64 imm)
{
  std::stringstream stream;

  if (checkAlreadyRegTainted(reg)){
    std::cout << "[Constraint]\t\t" << "#" << std::dec << uniqueID << " = xor(#" << getRegID(reg) << ", 0x" << std::hex << std::setfill('0') << std::setw(2) 
      << imm << ")" << std::endl;
    stream << "xor(#" << getRegID(reg) << ", 0x" << std::hex << std::setfill('0') << std::setw(2) << imm << ")";
    constraintList.push_back(make_pair(uniqueID, stream.str()));
    setRegID(reg,  uniqueID++);

    /* Construct the z3 equation */
    *z3Equation = (*z3Var ^ static_cast<int>(imm));
  }
}

VOID z3SolveEqViaCmp(INT32 cmpVal)
{
    std::cout << "[Z3 Solver]-------------------------------------" << std::endl;
    *z3Equation = (*z3Equation == cmpVal);
    z3Solver->add(*z3Equation);
    z3Solver->check();
    z3Model = new z3::model(z3Solver->get_model());
    std::cout << Z3_solver_to_string(*z3Context, *z3Solver) << std::endl;
    std::cout << Z3_model_to_string(*z3Context, *z3Model) << std::endl;

    unsigned int goodValue; 
    Z3_get_numeral_uint(*z3Context, z3Model->get_const_interp((*z3Model)[0]), &goodValue); 
    std::cout << "The good value is 0x" << std::hex << goodValue << std::endl;

    goodSerial[offsetSerial++] = goodValue;

    delete z3Model;
    delete z3Equation;
    delete z3Var;
    delete z3Solver;
    delete z3Context;
    std::cout << "[Z3 Solver]-------------------------------------" << std::endl;
}

VOID cmpRegReg(REG reg0, REG reg1, CONTEXT *ctx)
{
  std::stringstream stream;

  if (checkAlreadyRegTainted(reg0)){
    if (getRegID(reg1) != 0xffffffffffffffff){
      std::cout << "[Equation]\t\t" << "cmp(#" << std::dec << getRegID(reg0) << ", #" << getRegID(reg1) << ")" << std::endl;
      stream << "cmp(#" << std::dec << getRegID(reg0) << ", #" << getRegID(reg1) << ")";
    }
    else{
      std::cout << "[Equation]\t\t" << "cmp(#" << std::dec << getRegID(reg0) << ", 0x" << std::hex << std::setfill('0') << std::setw(2) 
        << PIN_GetContextReg(ctx, getHighReg(reg1)) << ")" << std::endl;
      stream << "cmp(#" << std::dec << getRegID(reg0) << ", 0x" << std::hex << std::setfill('0') << std::setw(2)
        << PIN_GetContextReg(ctx, getHighReg(reg1)) << ")";
    }

    std::cout << "[Equation]\t\t" << getFullEquation(stream.str()) << std::endl;
    z3SolveEqViaCmp(static_cast<int>(PIN_GetContextReg(ctx, getHighReg(reg1))));
  }
}

VOID cmpRegImm(REG reg, UINT64 imm)
{
  std::stringstream stream;

  if (checkAlreadyRegTainted(reg)){
    std::cout << "[Equation]\t\t" << "cmp(#" << std::dec << getRegID(reg) << ", 0x" << std::hex << std::setfill('0') << std::setw(2) 
      << imm << ")" << std::endl;
    stream << "cmp(#" << std::dec << getRegID(reg) << ", 0x" << std::hex << std::setfill('0') << std::setw(2) << imm << ")";
    constraintList.push_back(make_pair(uniqueID, stream.str()));

    std::cout << "[Equation]\t\t" << getFullEquation(stream.str()) << std::endl;
    z3SolveEqViaCmp(static_cast<int>(imm));
  }
}

VOID movRegReg(REG reg0, REG reg1, CONTEXT *ctx)
{
  std::stringstream stream;

  if (checkAlreadyRegTainted(reg0)){
    if (getRegID(reg1) != 0xffffffffffffffff){
      std::cout << "[Constraint]\t\t" << "#" << std::dec << uniqueID << " = #" << getRegID(reg1) << std::endl;
      stream << "#" << getRegID(reg1);
    }
    else{
      std::cout << "[Constraint]\t\t" << "#" << std::dec << uniqueID << " = 0x" << std::hex << std::setfill('0') << std::setw(2) 
        << PIN_GetContextReg(ctx, getHighReg(reg1)) << std::endl;
      stream << "0x" << std::hex << std::setfill('0') << std::setw(2) << PIN_GetContextReg(ctx, getHighReg(reg1));
    }
    constraintList.push_back(make_pair(uniqueID, stream.str()));
    setRegID(reg0,  uniqueID++);
  }
}

VOID Instruction(INS ins, VOID *v)
{
  if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_OperandCount(ins),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_UINT32, INS_RegW(ins, 0),
        IARG_END);
  }
  
  if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)followData,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_UINT32, INS_RegR(ins, 0),
        IARG_END);
  }

  /* xor reg, reg */
  if (INS_OperandCount(ins) > 1 && INS_Opcode(ins) == XED_ICLASS_XOR && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)xorRegReg,
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_END);
  }
  /* xor reg, imm */
  else if (INS_OperandCount(ins) > 1 && INS_Opcode(ins) == XED_ICLASS_XOR && INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)xorRegImm,
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_ADDRINT, INS_OperandImmediate(ins, 1),
        IARG_END);
  }
  /* cmp reg, reg */
  else if (INS_OperandCount(ins) > 1 && INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)cmpRegReg,
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_CONTEXT,
        IARG_END);
  }
  /* cmp reg, Imm */
  else if (INS_OperandCount(ins) > 1 && INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsReg(ins, 0) && INS_OperandIsImmediate(ins, 1)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)cmpRegImm,
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_ADDRINT, INS_OperandImmediate(ins, 1),
        IARG_END);
  }
  /* mov reg, reg */
  else if (INS_OperandCount(ins) > 1 && INS_Opcode(ins) == XED_ICLASS_MOV && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)movRegReg,
        IARG_UINT32, INS_OperandReg(ins, 0),
        IARG_UINT32, INS_OperandReg(ins, 1),
        IARG_CONTEXT,
        IARG_END);
  }


}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  unsigned int i;
  UINT64 start, size, fd;

  if (PIN_GetSyscallNumber(ctx, std) == __NR_open){
    std::string fileName(reinterpret_cast<const char *>(PIN_GetSyscallArgument(ctx, std, 0)));

    if (fileName == KnobTaintFile.Value())
      flag = 1;
  }
  else if (PIN_GetSyscallNumber(ctx, std) == __NR_close){
    fd = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));

    if (fd == targetedFd)
      targetedFd = 0;
  }
  else if (PIN_GetSyscallNumber(ctx, std) == __NR_read){
    fd    = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 0)));
    start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
    size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

    if (fd != targetedFd)
      return;

    for (i = 0; i < size; i++)
      addressTainted.push_back(start+i);
    
    std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
  }
}

VOID Syscall_exit(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  if (flag){
    targetedFd = PIN_GetSyscallReturn(ctx, std);
    flag = 0;
  }
}

VOID writeSerial(INT32 code, VOID *v)
{
  FILE *trace;

  trace = fopen(KnobTaintFile.Value().c_str(), "w");
  fprintf(trace, "%s", goodSerial);
  fclose(trace);

  return;
}

int main(int argc, char *argv[])
{
  if(PIN_Init(argc, argv)){
      return Usage();
  }
 
  PIN_SetSyntaxIntel();
  PIN_AddSyscallEntryFunction(Syscall_entry, 0);
  PIN_AddSyscallExitFunction(Syscall_exit, 0);
  INS_AddInstrumentFunction(Instruction, 0);

  PIN_AddFiniFunction(writeSerial, 0);
  PIN_StartProgram();

  return 0;
}

