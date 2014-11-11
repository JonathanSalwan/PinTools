//
//  Jonathan Salwan - Copyright (C) 2014-11-11
// 
//  http://shell-storm.org
//  http://twitter.com/JonathanSalwan
//
//  Note: PoC - Detect a format string vulnerability without pattern matching.
//
//  In this PoC, we can see that it's possible to detect some format string bugs without 
//  pattern matching (e.g: looking for %s or something like that). We only focus on the 
//  taint analysis and look if the va_arg based functions' first argument is tainted or 
//  not. 
//
//  Let's take an example by monitoring printf. On x86_64, we know that the RDI register 
//  holds the first argument. So, if RDI points to a tainted memory area, it's probably 
//  means that we can trigger a bug, otherwise it's safe.
//  
//  In this PoC, I only taint bytes comming from files by monitoring the syscall sys_open.
//  Feel free to add other syscalls and/or environements (argv...).
//
//  Let's use this following vulnerable code as an example:
//
//        | void foo(char *buf)
//        | {
//        |   unsigned int i;
//        |   char *ptr;
//        |
//        |   if (!(ptr = malloc(8)))
//        |     return;
//        |
//        |   for (i = 0; i < 8; i++)
//        |     ptr[i] = buf[i]; /* spread the taint to another area */
//        |
//        |   printf(ptr);       /* warn format string */
//        | }
//        |
//        | int main(int ac, char **av)
//        | {
//        |   int  fd;
//        |   char *buf;
//        |
//        |   if (!(buf = malloc(8)))
//        |     return -1;
//        |            
//        |   fd = open("./file.txt", O_RDONLY);
//        |   read(fd, buf, 8); /* The range [buff, buff+32] is tainted */
//        |   close(fd);
//        |
//        |   foo(buf); 
//        | }
//
// And now, let's run the Pin tool:
//  
//        | $ ../../../pin -t ./obj-intel64/frmtstr.so -- ./test
//        | [TAINT]                 bytes tainted from 0x874010 to 0x874018 (via read)
//        | [READ in 874010]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is now tainted
//        | [WRITE in 874030]       4006d0: mov byte ptr [rdx], al
//        |                         874030 is now tainted
//        | [READ in 874011]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874031]       4006d0: mov byte ptr [rdx], al
//        |                         874031 is now tainted
//        | [READ in 874012]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874032]       4006d0: mov byte ptr [rdx], al
//        |                         874032 is now tainted
//        | [READ in 874013]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874033]       4006d0: mov byte ptr [rdx], al
//        |                         874033 is now tainted
//        | [READ in 874014]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874034]       4006d0: mov byte ptr [rdx], al
//        |                         874034 is now tainted
//        | [READ in 874015]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874035]       4006d0: mov byte ptr [rdx], al
//        |                         874035 is now tainted
//        | [READ in 874016]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874036]       4006d0: mov byte ptr [rdx], al
//        |                         874036 is now tainted
//        | [READ in 874017]        4006cd: movzx eax, byte ptr [rax]
//        |                         eax is already tainted
//        | [WRITE in 874037]       4006d0: mov byte ptr [rdx], al
//        |                         874037 is now tainted
//        | [SPREAD]                4006e3: mov eax, 0x0
//        |                         output: eax | input: constant
//        |                         eax is now freed
//        | [frmtstr]               printf() is called
//        | [frmtstr]               RDI content: ABCD
//        | [frmtstr]               The RDI memory area is tagged as tainted
//        | [frmtstr]               This printf is probably vulnerable
//        | [READ in 874030]        7f764d19fd43: movdqu xmm0, xmmword ptr [rdi]
//        |                         xmm0 can't be tainted
//        | [READ in 874030]        7f764d18935c: movzx esi, byte ptr [rbx]
//        |                         esi is now tainted
//        | [SPREAD]                7f764d1885b5: mov ebp, esi
//        |                         output: ebp | input: esi
//        |                         ebp can't be tainted
//        | [FOLLOW]                7f764d1885b5: mov ebp, esi
//        | [READ in 874031]        7f764d18935c: movzx esi, byte ptr [rbx]
//        |                         esi is already tainted
//        | [SPREAD]                7f764d1885b5: mov ebp, esi
//        |                         output: ebp | input: esi
//        |                         ebp can't be tainted
//        | [FOLLOW]                7f764d1885b5: mov ebp, esi
//        | [READ in 874032]        7f764d18935c: movzx esi, byte ptr [rbx]
//        |                         esi is already tainted
//        | [SPREAD]                7f764d1885b5: mov ebp, esi
//        |                         output: ebp | input: esi
//        |                         ebp can't be tainted
//        | [FOLLOW]                7f764d1885b5: mov ebp, esi
//        | [READ in 874033]        7f764d18935c: movzx esi, byte ptr [rbx]
//        |                         esi is already tainted
//        | [SPREAD]                7f764d1885b5: mov ebp, esi
//        |                         output: ebp | input: esi
//        |                         ebp can't be tainted
//        | [FOLLOW]                7f764d1885b5: mov ebp, esi
//        | [SPREAD]                7f764d148318: mov esi, ebx
//        |                         output: esi | input: ebx
//        |                         esi is now freed
//
//
// As you can see, the Pin tool spreads the taint and raises a warning when printf is called
// In this case, it's easier to define the vulnerability model like that than to check if the 
// first argument contains a secure string format (%s, %32s, %x, ...).
//
// This scenario is not limited to printf, we can also define a set of functions that uses
// va_args and might be vulnerable as well.
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



struct mallocArea
{
  UINT64  base;
  UINT64  size;
  BOOL    status;
};

UINT32 lockTaint = LOCKED;

std::list<UINT64>               addressTainted;
std::list<REG>                  regsTainted;
std::list<struct mallocArea>    mallocAreaList;

INT32 Usage()
{
    std::cerr << "PoC - frmtstr" << std::endl;
    return -1;
}

BOOL checkAlreadyRegTainted(REG reg)
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

BOOL taintReg(REG reg)
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

BOOL removeRegTainted(REG reg)
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

VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp, UINT64 sp)
{
  list<UINT64>::iterator i;
  list<struct mallocArea>::iterator i2;
  UINT64 addr = memOp;
 
  if (opCount != 2)
    return;

  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (addr == *i){
        std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
        taintReg(reg_r);
        return;
      }
  }
  if (checkAlreadyRegTainted(reg_r)){
    std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
    removeRegTainted(reg_r);
  }
}

VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp, UINT64 sp)
{
  list<UINT64>::iterator i;
  list<struct mallocArea>::iterator i2;
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
    }
    else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
      std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
      std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
      taintReg(reg_w);
    }
  }
}

VOID followData(UINT64 insAddr, std::string insDis, REG reg)
{
  if (!REG_valid(reg))
    return;

  if (checkAlreadyRegTainted(reg)){
      std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
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
        IARG_REG_VALUE, REG_STACK_PTR,
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
        IARG_REG_VALUE, REG_STACK_PTR,
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
}

VOID checkFormatString(ADDRINT rdi)
{
  list<UINT64>::iterator i;
  std::string content = std::string((const char *)rdi);

  std::cout << "[frmtstr] \t\tprintf() is called" << std::endl;
  std::cout << "[frmtstr] \t\tRDI content: " << content << std::endl;  

  for(i = addressTainted.begin(); i != addressTainted.end(); i++){
      if (rdi == *i){
        std::cout << "[frmtstr] \t\tThe RDI memory area is tagged as tainted" << std::endl;
        if (content.find("%s") == string::npos)
          std::cout << "[frmtstr] \t\tThis printf is probably vulnerable" << std::endl;
        return;
      }
  }
}

VOID Image(IMG img, VOID *v)
{
  RTN printfRtn = RTN_FindByName(img, "printf");

  if (RTN_Valid(printfRtn)){
    RTN_Open(printfRtn);

    RTN_InsertCall(
        printfRtn, 
        IPOINT_BEFORE, (AFUNPTR)checkFormatString,
        IARG_REG_VALUE, REG_RDI,
        IARG_END);

    RTN_Close(printfRtn);
  }
}

static unsigned int tryksOpen;

#define TRICKS(){if (tryksOpen++ == 0)return;}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
  unsigned int i;
  UINT64 start, size;

  if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

      TRICKS(); /* tricks to ignore the first open */

      start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
      size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

      for (i = 0; i < size; i++)
        addressTainted.push_back(start+i);
      
      std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start+size << " (via read)"<< std::endl;
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
    PIN_AddSyscallEntryFunction(Syscall_entry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    
    return 0;
}

