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
//  Note: In-Memory Fuzzing with Pin
//        http://shell-storm.org/blog/In-Memory-fuzzing-with-Pin/
//
//  Vulnerable example:
//
//  400584 <foo>:
//  400584: 55                    push   rbp
//  400585: 48 89 e5              mov    rbp,rsp
//  400588: 48 83 ec 10           sub    rsp,0x10
//  40058c: 89 7d fc              mov    DWORD PTR [rbp-0x4],edi
//  40058f: 48 89 75 f0           mov    QWORD PTR [rbp-0x10],rsi
//  400593: 8b 45 fc              mov    eax,DWORD PTR [rbp-0x4]
//  400596: 48 98                 cdqe   
//  400598: 48 03 45 f0           add    rax,QWORD PTR [rbp-0x10]
//  40059c: 0f b6 00              movzx  eax,BYTE PTR [rax]
//  40059f: 0f be d0              movsx  edx,al
//  4005a2: b8 2c 07 40 00        mov    eax,0x40072c
//  4005a7: 89 d6                 mov    esi,edx
//  4005a9: 48 89 c7              mov    rdi,rax
//  4005ac: b8 00 00 00 00        mov    eax,0x0
//  4005b1: e8 ba fe ff ff        call   400470 <printf@plt>
//  4005b6: c9                    leave  
//  4005b7: c3                    ret
//
//  Syntax based on the above code:
//  $ ../../../pin -t ./obj-intel64/InMemoryFuzzing.so -start 0x400584 -end 0x4005b7 -reg rdi -fuzzingType inc -maxValue 0x3000 -- ./test 1
//
//  The output will be like that:
//  [...]
//  [Save Context]
//  [CONTEXT]=----------------------------------------------------------
//  RAX = 0000000000000002 RBX = 0000000000000000 RCX = 00007fffb8f55170
//  RDX = 00007fffb8f542e0 RDI = 0000000000001d20 RSI = 00007fffb8f542e0
//  RBP = 00007fffb8f54310 RSP = 00007fffb8f542c8 RIP = 0000000000400585
//  +-------------------------------------------------------------------
//  +--> 400585: mov rbp, rsp
//  +--> 400588: sub rsp, 0x10
//  +--> 40058c: mov dword ptr [rbp-0x4], edi
//  +--> 40058f: mov qword ptr [rbp-0x10], rsi
//  +--> 400593: mov eax, dword ptr [rbp-0x4]
//  +--> 400596: cdqe 
//  +--> 400598: add rax, qword ptr [rbp-0x10]
//  +--> 40059c: movzx eax, byte ptr [rax]
//  
//  SIGSEGV received
//  [SIGSGV]=----------------------------------------------------------
//  RAX = 00007fffb8f56000 RBX = 0000000000000000 RCX = 00007fffb8f55170
//  RDX = 00007fffb8f542e0 RDI = 0000000000001d20 RSI = 00007fffb8f542e0
//  RBP = 00007fffb8f542c8 RSP = 00007fffb8f542b8 RIP = 000000000040059c
//  +-------------------------------------------------------------------
//
//  
//  We got a SIGSEGV if RDI = 0x1d20
//

#include "pin.H"
#include <asm/unistd.h>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <list>
#include <unistd.h>

#define LOCKED        1
#define UNLOCKED      !LOCKED

#define CONTEXT_FLG   0
#define SIGSEGV_FLG   1

struct memoryInput
{
  ADDRINT address;
  UINT64  value;
};

struct regRef
{
  std::string       name;
  LEVEL_BASE::REG   ref;
};

static UINT32                   _lock = LOCKED;
std::list<struct memoryInput>   memInput;
CONTEXT                         snapshot;

/* Required arg */
KNOB<ADDRINT> KnobStart(KNOB_MODE_WRITEONCE, "pintool", "start", "0", "The start address of the fuzzing area");
KNOB<ADDRINT> KnobEnd(KNOB_MODE_WRITEONCE, "pintool", "end", "0", "The end address of the fuzzing area");
KNOB<string>  KnobREG(KNOB_MODE_WRITEONCE, "pintool", "reg", "none", "The register which will be fuzzed");

/* Optinal arg */
KNOB<ADDRINT> KnobStartValue(KNOB_MODE_WRITEONCE, "pintool", "startValue", "0", "The start value");
KNOB<ADDRINT> KnobMaxValue(KNOB_MODE_WRITEONCE, "pintool", "maxValue", "0xffffffff", "The end value");
KNOB<string>  KnobFuzzType(KNOB_MODE_WRITEONCE, "pintool", "fuzzingType", "none", "Type of fuzzing: incremental or random");

static struct regRef regsRef[] =
{
  {"rax", LEVEL_BASE::REG_RAX},
  {"rbx", LEVEL_BASE::REG_RBX},
  {"rcx", LEVEL_BASE::REG_RCX},
  {"rdx", LEVEL_BASE::REG_RDX},
  {"rdi", LEVEL_BASE::REG_RDI},
  {"rsi", LEVEL_BASE::REG_RSI},
  {"eax", LEVEL_BASE::REG_EAX},
  {"ebx", LEVEL_BASE::REG_EBX},
  {"ecx", LEVEL_BASE::REG_ECX},
  {"edx", LEVEL_BASE::REG_EDX},
  {"edi", LEVEL_BASE::REG_EDI},
  {"esi", LEVEL_BASE::REG_ESI},
  {"ah",  LEVEL_BASE::REG_AH},
  {"bh",  LEVEL_BASE::REG_BH},
  {"ch",  LEVEL_BASE::REG_CH},
  {"dh",  LEVEL_BASE::REG_DH},
  {"al",  LEVEL_BASE::REG_AL},
  {"bl",  LEVEL_BASE::REG_BL},
  {"cl",  LEVEL_BASE::REG_CL},
  {"dl",  LEVEL_BASE::REG_DL},
  {"dil", LEVEL_BASE::REG_DIL},
  {"sil", LEVEL_BASE::REG_SIL},
  {"",    REG_INVALID()}
};

INT32 Usage()
{
    std::cerr << "In-Memory Fuzzing tool" << std::endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID displayCurrentContext(CONTEXT *ctx, UINT32 flag)
{
  std::cout << "[" << (flag == CONTEXT_FLG ? "CONTEXT" : "SIGSGV") 
    << "]=----------------------------------------------------------" << std::endl;
  std::cout << std::hex << std::internal << std::setfill('0') 
    << "RAX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RAX) << " " 
    << "RBX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBX) << " " 
    << "RCX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RCX) << std::endl
    << "RDX = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDX) << " " 
    << "RDI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RDI) << " " 
    << "RSI = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSI) << std::endl
    << "RBP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RBP) << " "
    << "RSP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RSP) << " "
    << "RIP = " << std::setw(16) << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RIP) << std::endl;
  std::cout << "+-------------------------------------------------------------------" << std::endl;
}

static UINT32 fuzzValue;

VOID randomizeREG(CONTEXT *ctx, ADDRINT nextInsAddr)
{
  UINT32 i;

  if (KnobFuzzType.Value() == "random"){
    sleep(1);
    srand(time(NULL));
    fuzzValue = (rand() % (KnobMaxValue.Value() - KnobStartValue.Value())) + KnobStartValue.Value();
  }
  else if (KnobFuzzType.Value() == "inc"){
    fuzzValue++;
  }

  for (i = 0; !(regsRef[i].name.empty()); i++){
    if (regsRef[i].name == KnobREG.Value()){
      PIN_SetContextReg(ctx, regsRef[i].ref, fuzzValue);
      break;
    }
  }

  PIN_SetContextReg(ctx, LEVEL_BASE::REG_RIP, nextInsAddr);
}

VOID restoreMemory(void)
{
  list<struct memoryInput>::iterator i;

  for(i = memInput.begin(); i != memInput.end(); ++i){
    *(reinterpret_cast<ADDRINT*>(i->address)) = i->value;
  }
  memInput.clear();
}

VOID insCallBack(ADDRINT insAddr, std::string insDis, CONTEXT *ctx, ADDRINT nextInsAddr)
{
  if (nextInsAddr == KnobStart.Value()){
    if (fuzzValue >= KnobMaxValue.Value()){
      std::cout << "[In-Memory fuzzing stoped. The program continue with the original context]" << std::endl;
      displayCurrentContext(ctx, CONTEXT_FLG);
      return PIN_RemoveInstrumentation();
    }
    std::cout << "[Save Context]" << std::endl;
    PIN_SaveContext(ctx, &snapshot);
    randomizeREG(ctx, nextInsAddr);
    displayCurrentContext(ctx, CONTEXT_FLG);
    _lock = UNLOCKED;
    PIN_ExecuteAt(ctx);
  }
  
  if (_lock == LOCKED)
    return;

  std::cout << "+--> " << std::hex << insAddr << ": " << insDis << std::endl;
  
  if (insAddr == KnobEnd.Value()){
    _lock = LOCKED;
    std::cout << "[Restore Context]" << std::endl;
    PIN_SaveContext(&snapshot, ctx);
    restoreMemory();
    PIN_ExecuteAt(ctx);
  }
}

VOID WriteMem(ADDRINT insAddr, std::string insDis, ADDRINT memOp)
{
  struct memoryInput elem;
  ADDRINT addr = memOp;

  if (_lock == LOCKED)
    return;

  elem.address = addr;
  elem.value = *(reinterpret_cast<ADDRINT*>(addr));
  memInput.push_back(elem);
}

VOID Instruction(INS ins, VOID *v)
{
  PIN_LockClient();
  IMG img = IMG_FindByAddress(INS_Address(ins));
  PIN_UnlockClient();
  
  if (IMG_Valid(img) && IMG_IsMainExecutable(img)){
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)insCallBack,
                   IARG_ADDRINT, INS_Address(ins),
                   IARG_PTR, new string(INS_Disassemble(ins)),
                   IARG_CONTEXT,
                   IARG_ADDRINT, INS_NextAddress(ins),
                   IARG_END);
  }

  if (INS_MemoryOperandIsWritten(ins, 0)){
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
                   IARG_ADDRINT, INS_Address(ins),
                   IARG_PTR, new string(INS_Disassemble(ins)),
                   IARG_MEMORYOP_EA, 0,
                   IARG_END);
  }
}

BOOL catchSignal(THREADID tid, INT32 sig, CONTEXT *ctx, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
  std::cout << std::endl << std::endl << "/!\\ SIGSEGV received /!\\" << std::endl;
  displayCurrentContext(ctx, SIGSEGV_FLG);
  return true;
}

int main(int argc, char *argv[])
{
    if(PIN_Init(argc, argv)){
        return Usage();
    }
    
    if (!KnobStart.Value() || !KnobEnd.Value() || !KnobREG.Value().empty())
      return Usage();

    if (KnobStartValue.Value() > KnobMaxValue.Value())
      return Usage();

    fuzzValue = KnobStartValue.Value() - 1;

    PIN_SetSyntaxIntel();
    PIN_InterceptSignal(SIGSEGV, catchSignal, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    
    return 0;
}

