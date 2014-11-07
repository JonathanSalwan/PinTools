//
//  Jonathan Salwan - Copyright (C) 2013-08
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Example 1 - http://shell-storm.org/blog/Taint-analysis-with-Pin/
//        Simple taint memory area from read syscall. 
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

/* bytes range tainted */
struct range
{
  UINT64 start;
  UINT64 end;
};

std::list<struct range> bytesTainted;

INT32 Usage()
{
    cerr << "Ex 1" << endl;
    return -1;
}

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct range>::iterator i;
  UINT64 addr = memOp;
  
  for(i = bytesTainted.begin(); i != bytesTainted.end(); ++i){
      if (addr >= i->start && addr < i->end){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis<< std::endl;
      }
  } 
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT64 memOp)
{
  list<struct range>::iterator i;
  UINT64 addr = memOp;

  for(i = bytesTainted.begin(); i != bytesTainted.end(); ++i){
      if (addr >= i->start && addr < i->end){
        std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
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
}

static unsigned int lock;

#define TRICKS(){if (lock++ == 0)return;}

/* Taint from Syscalls */
VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  struct range taint;

  /* Taint from read */
  if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

      TRICKS();

      taint.start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
      taint.end   = taint.start + static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
      bytesTainted.push_back(taint);
      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << taint.start << " to 0x" << taint.end << " (via read)"<< std::endl;
  }
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    
    PIN_SetSyntaxIntel();
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    
    return 0;
}

