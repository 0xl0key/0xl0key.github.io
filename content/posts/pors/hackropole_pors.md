---
title: "Hackropole : PORS"
date: 2025-10-12T21:07:38+02:00
draft: false
toc: false
images:
tags:
  - reverse
---

This writeup is for the PORS challenge from Hackropole, a 2-star difficulty challenge.
## Reconnaissance

The binary is in ELF format, x86_64 architecture and is stripped:
```bash
l0key at dev in [~/Documents/hackropole/pors]
19:39:09 › file pors
pors: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e03394fc3f442e87fd6114acbff6082426e4a652, for GNU/Linux 3.2.0, stripped
```

A first execution shows that it asks for input:
```bash
l0key at dev in [~/Documents/hackropole/pors]
19:39:12 › ./pors
Enter your input: test
[-] Wrong input, sorry...
```

There's also a file containing raw data alongside the executable (program.bin).
### Initial Analysis with Ghidra

We decompile the PORS program with Ghidra to find the steps that validate our input. Ghidra gives us this C pseudo-code:
```C
int main(void)

{
  uint buf_2;
  uint buf_one;
  void *p3;
  void *p2;
  void *p1;
  FILE *fdesc;
  
  fdesc = fopen("program.bin","r");
  if (fdesc == (FILE *)0x0) {
    puts("[-] Failed to load program :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread(&buf_one,4,1,fdesc);
  p1 = mmap((void *)0x13370000,(long)(int)((buf_one & 0xfffff000) + 0x1000),7,0x22,-1,0);
  if (p1 != (void *)0x13370000) {
    puts("[-] init failed, sorry :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread((void *)0x13370000,1,(long)(int)buf_one,fdesc);
  fread(&buf_2,4,1,fdesc);
  p2 = mmap((void *)0x42420000,(long)(int)((buf_2 & 0xfffff000) + 0x1000),3,0x22,-1,0);
  if (p2 != (void *)0x42420000) {
    puts("[-] init failed, sorry :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fread((void *)0x42420000,1,(long)(int)buf_2,fdesc);
  p3 = mmap((void *)0xcafe0000,0x2000,3,0x22,-1,0);
  if (p3 != (void *)0xcafe0000) {
    puts("[-] init failed, sorry :/");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  syscall();
  return 0;
}
```
Without going too far, we can already see there's an issue. Indeed, we don't see anywhere a part that retrieves and validates our input.

However, we can observe that the program.bin file is read and stored in memory regions of our process.

The way it's read should catch our attention. We can see that the data is divided into 3 specific memory regions (0x13370000, 0x42420000 and 0xcafe0000) and that mmap gives precise permissions to these memory regions. More specifically, the first mmap gives RWX permissions to the memory region starting at 0x13370000. Moreover, we can see that the file is parsed in a precise manner: we first read 4 bytes at the beginning of the file which are used in the size parameter of mmap, then we use these 4 bytes again to read a certain number of bytes into the allocated memory region. This means that each section in the program.bin file starts with information about its size.

All of this indicates that the rest of the program's logic is in program.bin.

Finally, we can see that we have a syscall at the end of main. Looking at the assembly code more closely, we can get more information:
```asm
MOV        RSP,0x42420000
MOV        RAX,0xf
SYSCALL
```

RSP now contains the address 0x42420000 and the syscall number is 0xf, which corresponds to the syscall: rt_sigreturn.

Searching a bit on the internet and with the help of the challenge title, we come across an exploitation technique called SROP.

This technique abuses signal handling under Linux/Unix.
## Description of SROP

First, we need to understand how signal handling works under Linux.

When a process receives a signal (SIGSEGV, SIGINT...), it proceeds as follows:
1. The kernel saves the context, i.e., all registers and flags.
2. A signal handler executes.
3. Return to the program via the sigreturn syscall (syscall 15) which restores all registers from the stack.

SROP abuses this system by forging a fake signal frame representing the context and then calling the sigreturn syscall. Thus, the program resumes with the fake frame, with register values that we control.

The fake signal frame looks like this:
![[frame.png]]
## Extracting the Real Program

Our program here uses the SROP technique to execute the real program, which verifies our input.

Here, the memory region starting at 0x13370000 contains the code that will be executed, the memory region 0x42420000 contains the fake stack frame, and 0xcafe0000 is likely used as a memory region for the SROP program.

To understand what our program really does, I wrote a C program to extract from program.bin the code present at 0x13370000, using the same principle as the pors program to parse it:
```C
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>

int get_code_section(const unsigned char buf[], const int buf_size)
{
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    return EXIT_FAILURE;
  }

  count = cs_disasm(handle, buf, buf_size-1, 0x13370000, 0, &insn);

  if (count > 0) {
    size_t i;

    for (i = 0; i < count; i++) {
      printf("0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic,
             insn[i].op_str);
    }
  } else {
    printf("Error: Failed to disassemble given code!\n");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
  FILE* file;
  uint32_t size;

  file = fopen("program.bin", "rb");
  if (!file) {
    printf("Erreur ouverture fichier\n");
  }

  fread(&size, 4, 1, file);

  unsigned char *buf = malloc(size);

  fread(buf, 1 , size, file);
  printf("%d", size);

  if(get_code_section(buf, size)) {
    printf("Error disassembling code section !\n");
  }

  fclose(file);
  free(buf);

  return EXIT_SUCCESS;
}
```

This displays several blocks separated by garbage code:
```asm
0x13370000:	mov		rax, rdx
0x13370003:	add		rax, 1
0x13370007:	imul		rax, rax, 0xf8
0x1337000e:	add		rsp, rax
0x13370011:	mov		rax, 0xf
0x13370018:	syscall		
...
0x13370050:	syscall		
0x13370052:	mov		rsp, 0x42420000
0x13370059:	mov		qword ptr [rsp + 0x88], 0x40
0x13370065:	mov		rax, 0xf
0x1337006c:	syscall		
...
0x133700a0:	cmp		dword ptr [rsp + 8], eax
0x133700a4:	mov		rsp, 0x42420000
0x133700ab:	mov		rax, 0x2d
0x133700b2:	mov		rbx, 0x21
0x133700b9:	cmovl		rax, rbx
0x133700bd:	mov		qword ptr [rsp + 0x88], rax
0x133700c5:	mov		rax, 0xf
0x133700cc:	syscall		
etc
```

Looking at the structure more closely, we can see that the program using SROP adds a layer of obfuscation, specifically Control Flow Flattening (CFF). Indeed, we can see that RSP is always filled with the address 0x42420000 and that the sigreturn syscall is called at the end of each block, which means that each block returns to the first block which handles dispatching to the next block. This is how CFF works. We can verify this with gdb:
```asm
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x0
$rdx   : 0x0
$rsp   : 0x0000000042420000  →  0x0000000000000000
$rbp   : 0x0
$rsi   : 0x0
$rdi   : 0x0
$rip   : 0x0000000013370000  →  0x4801c08348d08948
$r8    : 0x0
$r9    : 0x0
$r10   : 0x0
$r11   : 0x0
$r12   : 0x0
$r13   : 0x0
$r14   : 0x0
$r15   : 0x0
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x0000000042420000│+0x0000: 0x0000000000000000	 ← $rsp
0x0000000042420008│+0x0008: 0x0000000000000000
0x0000000042420010│+0x0010: 0x0000000000000000
0x0000000042420018│+0x0018: 0x0000000000000000
0x0000000042420020│+0x0020: 0x0000000000000000
0x0000000042420028│+0x0028: 0x0000000000000000
0x0000000042420030│+0x0030: 0x0000000000000000
0x0000000042420038│+0x0038: 0x0000000000000000
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
 → 0x13370000                  mov    rax, rdx
   0x13370003                  add    rax, 0x1
   0x13370007                  imul   rax, rax, 0xf8
   0x1337000e                  add    rsp, rax
   0x13370011                  mov    rax, 0xf
   0x13370018                  syscall
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pors", stopped 0x13370000 in ?? (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x13370000 → mov rax, rdx
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```
Here, I set a breakpoint right after the first syscall in the pors program. We can see that for rsp 0x42420000, the recovered stack frame has an rip register pointing to the code at 0x13370000. This block is therefore the dispatcher.

Looking more closely at the dispatcher block, we can see that it uses the rax register to calculate the address of the next fake frame, and that in some blocks we have conditional mov instructions, which will either set rax with the value of rbx or keep the base value of rax, which looks like an if/else structure.

## Deobfuscate

To deobfuscate this program, we need to emulate the dispatcher in order to replace the syscalls in each block with simple jmp instructions.

For this, I wrote a Python script to obtain the real program stored in program.bin:

```python
from pwn import *
from capstone import *

FRAME_SIZE = 0xf8
CODE_START_ADDR = 0x13370000
CODE_BLOCK_SIZE = 0x50

cmov_to_jmp = {
    'cmovne': 'jne',   
    'cmove':  'je',    
    'cmovg':  'jg',     
    'cmovl':  'jl',     
    'cmovle': 'jle',    
    'cmovge': 'jge',   
    'cmova':  'ja',     
    'cmovb':  'jb',     
    'cmovae': 'jae',    
    'cmovbe': 'jbe',    
    'cmovs':  'js',    
    'cmovns': 'jns',    
    'cmovo':  'jo',     
    'cmovno': 'jno',    
    'cmovc':  'jc',     
    'cmovnc': 'jnc',    
    'cmovz':  'jz',     
    'cmovnz': 'jnz',    
    'cmovp':  'jp',    
    'cmovnp': 'jnp', 
}

md = Cs(CS_ARCH_X86, CS_MODE_64)

# Reading sections
with open('program.bin', 'rb') as f:
    code_section_size = int.from_bytes(f.read(4), 'little')
    code_section = f.read(code_section_size)
    frame_section_size = int.from_bytes(f.read(4), 'little')
    frame_section = f.read(frame_section_size)

nb_frames = frame_section_size // FRAME_SIZE

frames_list = [SigreturnFrame(arch='amd64') for i in range(nb_frames)]
couple_frame_code = []
offset = 0

for i in range(nb_frames):
    offset = i*FRAME_SIZE
    frames_list[i].r8 = int.from_bytes(frame_section[offset+0x28 : offset+0x30], 'little')
    frames_list[i].r9 = int.from_bytes(frame_section[offset+0x30 : offset+0x38], 'little')
    frames_list[i].r10 = int.from_bytes(frame_section[offset+0x38 : offset+0x40], 'little')
    frames_list[i].r11 = int.from_bytes(frame_section[offset+0x40 : offset+0x48], 'little')
    frames_list[i].r12 = int.from_bytes(frame_section[offset+0x48 : offset+0x50], 'little')
    frames_list[i].r13 = int.from_bytes(frame_section[offset+0x50 : offset+0x58], 'little')
    frames_list[i].r14 = int.from_bytes(frame_section[offset+0x58 : offset+0x60], 'little')
    frames_list[i].r15 = int.from_bytes(frame_section[offset+0x60 : offset+0x68], 'little')
    frames_list[i].rdi = int.from_bytes(frame_section[offset+0x68 : offset+0x70], 'little')
    frames_list[i].rsi = int.from_bytes(frame_section[offset+0x70 : offset+0x78], 'little')
    frames_list[i].rbp = int.from_bytes(frame_section[offset+0x78 : offset+0x80], 'little')
    frames_list[i].rbx = int.from_bytes(frame_section[offset+0x80 : offset+0x88], 'little')
    frames_list[i].rdx = int.from_bytes(frame_section[offset+0x88 : offset+0x90], 'little')
    frames_list[i].rax = int.from_bytes(frame_section[offset+0x90 : offset+0x98], 'little')
    frames_list[i].rcx = int.from_bytes(frame_section[offset+0x98 : offset+0xa0], 'little')
    frames_list[i].rsp = int.from_bytes(frame_section[offset+0xa0 : offset+0xa8], 'little')
    frames_list[i].rip = int.from_bytes(frame_section[offset+0xa8 : offset+0xb0], 'little')

    # Create tuple(indice_code_block, indice_srop_frame)
    frame_code = (((frames_list[i].rip - CODE_START_ADDR) // CODE_BLOCK_SIZE), i)
    couple_frame_code.append(frame_code)

code_block = []

for el in couple_frame_code:
    offset = el[0] * CODE_BLOCK_SIZE
    code_block = code_section[offset : offset+0x50]

    load_frame = f"mov r8, {frames_list[el[1]].r8}\n"
    load_frame = load_frame + f"mov r9, 0x{frames_list[el[1]].r9:x}\n"
    load_frame = load_frame + f"mov r10, 0x{frames_list[el[1]].r10:x}\n"
    load_frame = load_frame + f"mov r11, 0x{frames_list[el[1]].r11:x}\n"
    load_frame = load_frame + f"mov r12, 0x{frames_list[el[1]].r12:x}\n"
    load_frame = load_frame + f"mov r13, 0x{frames_list[el[1]].r13:x}\n"
    load_frame = load_frame + f"mov r14, 0x{frames_list[el[1]].r14:x}\n"
    load_frame = load_frame + f"mov r15, 0x{frames_list[el[1]].r15:x}\n"
    load_frame = load_frame + f"mov rdi, 0x{frames_list[el[1]].rdi:x}\n"
    load_frame = load_frame + f"mov rsi, 0x{frames_list[el[1]].rsi:x}\n"
    load_frame = load_frame + f"mov rbp, 0x{frames_list[el[1]].rbp:x}\n"
    load_frame = load_frame + f"mov rbx, 0x{frames_list[el[1]].rbx:x}\n"
    load_frame = load_frame + f"mov rdx, 0x{frames_list[el[1]].rdx:x}\n"
    load_frame = load_frame + f"mov rax, 0x{frames_list[el[1]].rax:x}\n"
    load_frame = load_frame + f"mov rcx, 0x{frames_list[el[1]].rcx:x}\n"
    load_frame = load_frame + f"mov rsp, 0x{frames_list[el[1]].rsp:x}\n"

    print(load_frame)

    find_mov = False
    find_imm_rsp = False
    rax_imm = 0
    rbx_imm = 0
    rsp_imm = 0

    for i in md.disasm(code_block, 0x13370000 + offset):
        if el[0] != 0:
            if i.mnemonic == "add" and i.op_str == "byte ptr [rax], al":
                continue
            if "mov" in i.mnemonic and "rax" in i.op_str and "0x" in i.op_str:
                find_mov = True
                rax_imm = int(i.op_str.split(", ")[1], 16)
            if "mov" in i.mnemonic and "rbx" in i.op_str and "0x" in i.op_str:
                rbx_imm = int(i.op_str.split(", ")[1], 16)
            if "mov" in i.mnemonic and "qword ptr [rsp + 0x88]" in i.op_str and "rax" not in i.op_str:
                find_imm_rsp = True
                rsp_imm = int(i.op_str.split(", ")[1], 16)

            if find_mov:
                if "cmov" in i.mnemonic:
                    print(f"{cmov_to_jmp[i.mnemonic]} cond")
                    print(f"jmp {frames_list[rax_imm + 1].rip:x}")
                    print(f"cond:")
                    print(f"jmp {frames_list[rbx_imm + 1].rip:x}")
                    break
            elif find_imm_rsp:
                print(f"jmp {frames_list[rsp_imm + 1].rip:x}")
                break

            print(f"0x{i.address:x} {i.mnemonic} {i.op_str}")
    print("\n")
```

This Python script parses the program.bin file, displays each code block, replaces conditional mov instructions with jmps, and displays the stack frame used before each block.

## Solver

Since the generated program is quite substantial, you can pass it to an LLM to understand what it does.

The LLM tells us that the program implements a Suguru puzzle verifier. Our input is therefore used to solve this puzzle, and displays the flag in case of success.

By extracting the constraints from the verifier, we can write a solver with z3 to solve the puzzle:
```python
from z3 import *

constraints = [
    [0, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, 4, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 5, 0, 0],
    [0, 0, 0, 5, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 5, 0, 0, 4, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 2, 5, 0, 1],
]

areas = [
    [0,0,1,1,2,2,3,3,3],
    [0,0,4,4,2,2,2,3,3],
    [5,5,4,4,6,6,7,7,7],
    [8,5,5,4,9,6,10,7,7],
    [8,8,5,9,9,10,10,10,10],
    [11,8,12,9,9,13,13,13,13],
    [11,12,12,12,14,15,15,15,15],
    [11,12,14,14,14,16,15,17,17],
    [18,18,18,18,14,16,17,17,17],
]

grid = [[BitVec(f"x{i}{j}", 8) for j in range(9)] for i in range(9)]
s = Solver()

for i in range(9):
    for j in range(9):
        # values between 1 and 9
        s.add(And(grid[i][j] >= 1, grid[i][j] <= 9))
        # apply pre-filled values
        if constraints[i][j] != 0:
            s.add(grid[i][j] == constraints[i][j])
        # no repetition with neighbors (Suguru)
        if i < 8:
            s.add(grid[i][j] != grid[i+1][j])
            if j < 8:
                s.add(grid[i][j] != grid[i+1][j+1])
            if j > 0:
                s.add(grid[i][j] != grid[i+1][j-1])
        if i > 0:
            s.add(grid[i][j] != grid[i-1][j])
            if j < 8:
                s.add(grid[i][j] != grid[i-1][j+1])
            if j > 0:
                s.add(grid[i][j] != grid[i-1][j-1])
        if j < 8:
            s.add(grid[i][j] != grid[i][j+1])
        if j > 0:
            s.add(grid[i][j] != grid[i][j-1])

c_areas = [0]*0x13
s_areas = [0]*0x13

for i in range(9):
    for j in range(9):
        c_areas[areas[i][j]] += 1
        s_areas[areas[i][j]] += (1 << (grid[i][j] - 1))

for i in range(0x13):
    s.add(s_areas[i] == (1 << c_areas[i]) - 1)

if s.check() == sat:
    m = s.model()
    sol_mat = [[m[grid[i][j]].as_long() for j in range(9)] for i in range(9)]
    sol = ''.join(str(m[grid[i][j]].as_long()) for i in range(9) for j in range(9))
    print("Solution:", sol)
else:
    print("[-] Unable to solve the puzzle")
```

Running the solver, we find that the correct input is: `141253514235414232142323541235141232142323541231514132142323251351541434143232521`

Let's verify:
```bash
l0key at dev in [~/Documents/hackropole/pors]
20:56:17 › ./pors
Enter your input: 141253514235414232142323541235141232142323541231514132142323251351541434143232521
[+] Congratulations! You can validate the challenge with this flag: CWTE{pr0gr4mm4t10n_0r13nt33_r3t0ur_s1gn4l}
```

Thanks to spikeroot for this awesome challenge!

References:
https://man7.org/linux/man-pages/man7/signal.7.html
https://sthbrx.github.io/blog/2016/05/13/srop-mitigation/
https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
