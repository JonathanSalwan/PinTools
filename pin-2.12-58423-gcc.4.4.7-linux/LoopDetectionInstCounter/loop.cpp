//
//  Jonathan Salwan - 2013-08-13
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: Pin tool - Simple loop detection via the instruction counter.
//

#include "pin.H"
#include <asm/unistd.h>
#include <fstream>
#include <iostream>
#include <list>

#define LOCKED    1
#define UNLOCKED  !LOCKED

static UINT32       _lockAnalysis = !LOCKED; /* unlock -> without sym */
static UINT16       _tabAddr[0x10000];
static std::string  _tabStr[0x10000];

INT32 Usage()
{
    std::cerr << "Foo test" << std::endl;
    return -1;
}

VOID insCallBack(UINT64 insAddr, std::string insDis)
{
  if (_lockAnalysis)
    return ;

  if (insAddr > 0x700000000000)
    return;
 
  if (_tabAddr[insAddr ^ 0x400000] == 0xffff)
    return;
 
  _tabAddr[insAddr ^ 0x400000] += 1;
  _tabStr[insAddr ^ 0x400000] = insDis;

}

VOID Instruction(INS ins, VOID *v)
{
  INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)insCallBack,
      IARG_ADDRINT, INS_Address(ins),
      IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_END);
}

VOID unlockAnalysis(void)
{
  _lockAnalysis = UNLOCKED;
}

VOID lockAnalysis(void)
{
  _lockAnalysis = LOCKED;
}

VOID Image(IMG img, VOID *v)
{
  RTN mainRtn = RTN_FindByName(img, "main");

  if (RTN_Valid(mainRtn)){
    RTN_Open(mainRtn);
    RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)unlockAnalysis, IARG_END);
    RTN_InsertCall(mainRtn, IPOINT_AFTER, (AFUNPTR)lockAnalysis, IARG_END);
    RTN_Close(mainRtn);
  }
}

VOID Fini(INT32 code, VOID *v)
{
  UINT32 i;

  std::cout << "Addr\tNumber\tDisass" << std::endl;
  for (i = 0; i < 0x10000; i++){
    if (_tabAddr[i])
      std::cout << std::hex << (0x400000 + i) << "\t" << std::dec << _tabAddr[i] << "\t" << _tabStr[i] << std::endl;
  }
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    
    PIN_SetSyntaxIntel();
    //IMG_AddInstrumentFunction(Image, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    
    return 0;
}

