//
//  Jonathan Salwan - Copyright (C) 2013-08
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 6 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Detect pointer utilization without check
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

#define LOCKED    1
#define UNLOCKED  !LOCKED

#define ALLOCATE  1
#define FREE      !ALLOCATE

#define CHECKED   1

static size_t         lastSize;

struct mallocArea
{
  UINT64  base;
  UINT64  size;
  BOOL    status;
  BOOL    check;
};

UINT32 lockTaint = LOCKED;

std::list<UINT64>               addressTainted;
std::list<REG>                  regsTainted;
std::list<struct mallocArea>    mallocAreaList;

INT32 Usage()
{
    std::cerr << "Ex 6" << std::endl;
    return -1;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct mallocArea>::iterator i;
  UINT64 addr = memOp;

  for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
    if (i->base == addr && i->check != CHECKED)
      std::cout << std::hex << "[READ in " << addr << " without check]\t\t" << insAddr << ": " << insDis << std::endl;
  } 
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct mallocArea>::iterator i;
  UINT64 addr = memOp;
  
  for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
    if (i->base == addr && i->check != CHECKED)
      std::cout << std::hex << "[WRITE in " << addr << " without check]\t\t" << insAddr << ": " << insDis << std::endl;
  }
}

VOID cmpInst(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct mallocArea>::iterator i;
  UINT64 addr = memOp;

  for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
    if (*(UINT64 *)addr == i->base){
      //std::cout << std::hex << "[PTR " << *(UINT64 *)addr << " checked]\t\t\t" << insAddr << ": " << insDis << std::endl;
      i->check = CHECKED;
    }
  }
}

VOID testInst(UINT64 insAddr, std::string insDis, ADDRINT val_r0, ADDRINT val_r1)
{
  list<struct mallocArea>::iterator i;

  for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
    if (val_r0 == val_r1 && val_r0 == i->base){
      //std::cout << std::hex << "[PTR " << val_r0 << " checked]\t\t\t" << insAddr << ": " << insDis << std::endl;
      i->check = CHECKED;
    }
  }
}

VOID Instruction(INS ins, VOID *v)
{
  if (INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_Opcode(ins) == XED_ICLASS_CMP && INS_OperandIsMemory(ins, 0)){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)cmpInst,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_MEMORYOP_EA, 0,
        IARG_END);
  }
  else if (INS_Opcode(ins) == XED_ICLASS_TEST && INS_OperandCount(ins) >= 2 &&
           REG_valid(INS_OperandReg(ins, 0)) && REG_valid(INS_OperandReg(ins, 1))){
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)testInst,
        IARG_ADDRINT, INS_Address(ins),
        IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_REG_VALUE, INS_OperandReg(ins, 0),
        IARG_REG_VALUE, INS_OperandReg(ins, 1),
        IARG_END);
  }
}

VOID callbackBeforeMalloc(ADDRINT size)
{
  lastSize = size;
}

VOID callbackBeforeFree(ADDRINT addr)
{ 
  list<struct mallocArea>::iterator i;
  
  //std::cout << "[INFO]\t\t\t\t\tfree(" << std::hex << addr << ")" << std::endl;
  for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
    if (addr == i->base){
      i->status = FREE;
      break;
    }
  }
}

VOID callbackAfterMalloc(ADDRINT ret)
{
  list<struct mallocArea>::iterator i;
  struct mallocArea elem;

  //std::cout << "[INFO]\t\t\t\t\tmalloc(" << lastSize << ") = " << std::hex << ret << std::endl;
  if (ret){

    for(i = mallocAreaList.begin(); i != mallocAreaList.end(); i++){
      if (ret == i->base){
        i->status = ALLOCATE;
        i->size = lastSize;
        i->check = !CHECKED;
        return;
      }
    }
    elem.base = ret;
    elem.size = lastSize;
    elem.status = ALLOCATE;
    elem.check = !CHECKED;
    mallocAreaList.push_front(elem);
  }
}

VOID Image(IMG img, VOID *v)
{
  RTN mallocRtn = RTN_FindByName(img, "malloc");
  RTN freeRtn = RTN_FindByName(img, "free");

  if (RTN_Valid(mallocRtn)){
    RTN_Open(mallocRtn);

    RTN_InsertCall(
        mallocRtn, 
        IPOINT_BEFORE, (AFUNPTR)callbackBeforeMalloc,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_END);

    RTN_InsertCall(
        mallocRtn, 
        IPOINT_AFTER, (AFUNPTR)callbackAfterMalloc,
        IARG_FUNCRET_EXITPOINT_VALUE, 
        IARG_END);

    RTN_Close(mallocRtn);
  }

  if (RTN_Valid(freeRtn)){
    RTN_Open(freeRtn);
    RTN_InsertCall(
        freeRtn, 
        IPOINT_BEFORE, (AFUNPTR)callbackBeforeFree,
        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
        IARG_END);
    RTN_Close(freeRtn);
  }
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    
    PIN_SetSyntaxIntel();
    IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    
    return 0;
}

