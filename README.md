# CyberThreat2019.Binary2
*Before getting confused, I used two different disassemblers here, thats why sometimes the memory address will jump way higher. Know that the image base for ghidra is 0x100000 and GDB(64bit elf) is 0x555555555000. I will often address the lines by their lower word*
**1. First impressions**
```
        00102030 89 7d ec        MOV        dword ptr [RBP + -0x14],RDI
        00102033 48 89 75 e0     MOV        qword ptr [RBP + -0x20],RSI
        00102037 c7 45 fc        MOV        dword ptr [RBP + -0x4],0x0
                 00 00 00 00
        0010203e 48 8d 3d        LEA        RDI,[s_What_is_the_answer_to_the_Ultima_001031   = "What is the answer to the Ult
                 bb 10 00 00
        00102045 e8 3b ff        CALL       FUN_00101f85                                        = "What is the answer to the Ult
                 ff ff                                                                       0010204a 48 8d 3d        LEA        RDI,[s_Couldn't_establish_an_input_prom_001031   = "Couldn't establish an input p
                 07 11 00 00
        00102051 e8 1a f0        CALL       fork                                             __pid_t fork(void)
                 ff ff
        00102056 48 8b 45 e0     MOV        RAX,qword ptr [RBP + -0x20]
        0010205a 48 8b 00        MOV        RAX,qword ptr [RAX]
        0010205d 8b 55 fc        MOV        EDX,dword ptr [RBP + -0x4]
        00102060 89 d6           MOV        RSI,EDX
        00102062 48 89 c7        MOV        RDI,RAX
        00102065 e8 9a fc        CALL       FUN_00101d04                                     undefined8 FUN_00101d04(char * p
                 ff ff
        0010206a b8 00 00        MOV        EAX,0x0
                 00 00
        0010206f c9              LEAVE
```
Notice the path being stored in memory
```
MOV        qword ptr [RBP + -0x20],RSI
```
Could be important later
And also a suspicious call to 0x00101f85. Why are we calling fork immediately afterwards instead of calling it in the function? Likely to do with the path and other variable that was placed on the stack just before.

After stepping into the first call, an extremely suspicious assignment of registers.
```
   0x555555555f8d    mov    qword ptr [rbp - 0x18], rdi
   0x555555555f91    mov    dword ptr [rbp - 4], 0
   0x555555555f98    mov    ecx, 0
   0x555555555f9d    mov    edx, 1
   0x555555555fa2    mov    esi, 0
   0x555555555fa7    mov    edi, 0
   0x555555555fac    mov    eax, 0
   0x555555555fb1    call   cosh@plt
```
This is suspicious because not only is it nothing like the input glibc cosh() takes, but anyone who has dealt with binaries before will immediately recognize this as *something bad*. Lets check out the function.

**2. Checking PLT and GOT**
```
pwndbg>! readelf binary2 -a
Relocation section '.rela.plt' at offset 0x710 contains 13 entries:
  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000005018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
000000005020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 strcpy@GLIBC_2.2.5 + 0
000000005028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 strtok@GLIBC_2.2.5 + 0
000000005030  000400000007 R_X86_64_JUMP_SLO 0000000000000000 fgets@GLIBC_2.17 + 0
000000005038  000600000007 R_X86_64_JUMP_SLO 0000000000000000 fork@GLIBC_2.2.5 + 0
000000005040  000700000007 R_X86_64_JUMP_SLO 0000000000000000 close@GLIBC_2.2.5 + 0
000000005048  000800000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
000000005050  000b00000007 R_X86_64_JUMP_SLO 0000000000000000 strlen@GLIBC_2.2.5 + 0
000000005058  000d00000007 R_X86_64_JUMP_SLO 0000000000000000 cosh@GLIBC_2.2.5 + 0
000000005060  000e00000007 R_X86_64_JUMP_SLO 0000000000000000 execve@GLIBC_2.2.5 + 0
000000005068  000f00000007 R_X86_64_JUMP_SLO 0000000000000000 strcmp@GLIBC_2.2.5 + 0
000000005070  001000000007 R_X86_64_JUMP_SLO 0000000000000000 listen@GLIBC_2.2.5 + 0
000000005078  001100000007 R_X86_64_JUMP_SLO 0000000000000000 @GLIBC_2.2.5 + 0
pwndbg> disassemble 0x5555555550b0
Dump of assembler code for function cosh@plt:
   0x00005555555550b0 <+0>:	jmp    QWORD PTR [rip+0x3fa2]        # 0x555555559058 <cosh@got.plt>
   0x00005555555550b6 <+6>:	push   0x8
   0x00005555555550bb <+11>:	jmp    0x555555555020
End of assembler dump.
pwndbg> x/2w 0x555555559058
0x555555559058 <cosh@got.plt>:	0xf7b618d0	0x00007fff
```
(The typical image base when debugging a 64bit elf in gdb is 0x555555555000, this time there was a little offset for some reason. Know that the address "should" have been 0x555555555058)

So now we have found the address of "cosh".
Lets remove the mask
```
pwndbg> disassemble 0x7ffff7b618d0
Dump of assembler code for function ptrace:
   0x00007ffff7b618d0 <+0>:	sub    rsp,0x68
   0x00007ffff7b618d4 <+4>:	lea    r8d,[rdi-0x1]
   0x00007ffff7b618d8 <+8>:	mov    QWORD PTR [rsp+0x38],rsi
   0x00007ffff7b618dd <+13>:	lea    r10,[rsp+0x8]
   0x00007ffff7b618e2 <+18>:	mov    QWORD PTR [rsp+0x40],rdx
   0x00007ffff7b618e7 <+23>:	mov    QWORD PTR [rsp+0x48],rcx
   0x00007ffff7b618ec <+28>:	mov    rax,QWORD PTR fs:0x28
   0x00007ffff7b618f5 <+37>:	mov    QWORD PTR [rsp+0x28],rax
   0x00007ffff7b618fa <+42>:	xor    eax,eax
   0x00007ffff7b618fc <+44>:	lea    rax,[rsp+0x70]
   0x00007ffff7b61901 <+49>:	cmp    r8d,0x3
   0x00007ffff7b61905 <+53>:	mov    DWORD PTR [rsp+0x10],0x18
   0x00007ffff7b6190d <+61>:	mov    QWORD PTR [rsp+0x18],rax
   0x00007ffff7b61912 <+66>:	lea    rax,[rsp+0x30]
   0x00007ffff7b61917 <+71>:	mov    esi,DWORD PTR [rax+0x8]
   0x00007ffff7b6191a <+74>:	mov    rdx,QWORD PTR [rax+0x10]
   0x00007ffff7b6191e <+78>:	cmovae r10,QWORD PTR [rax+0x18]
   0x00007ffff7b61923 <+83>:	mov    QWORD PTR [rsp+0x20],rax
   0x00007ffff7b61928 <+88>:	mov    eax,0x65
   0x00007ffff7b6192d <+93>:	syscall 
   0x00007ffff7b6192f <+95>:	cmp    rax,0xfffffffffffff000
   0x00007ffff7b61935 <+101>:	ja     0x7ffff7b61978 <ptrace+168>
   0x00007ffff7b61937 <+103>:	test   rax,rax
   0x00007ffff7b6193a <+106>:	js     0x7ffff7b61942 <ptrace+114>
   0x00007ffff7b6193c <+108>:	cmp    r8d,0x2
   0x00007ffff7b61940 <+112>:	jbe    0x7ffff7b61960 <ptrace+144>
   0x00007ffff7b61942 <+114>:	mov    rcx,QWORD PTR [rsp+0x28]
   0x00007ffff7b61947 <+119>:	xor    rcx,QWORD PTR fs:0x28
   0x00007ffff7b61950 <+128>:	jne    0x7ffff7b6198d <ptrace+189>
   0x00007ffff7b61952 <+130>:	add    rsp,0x68
   0x00007ffff7b61956 <+134>:	ret    
   0x00007ffff7b61957 <+135>:	nop    WORD PTR [rax+rax*1+0x0]
   0x00007ffff7b61960 <+144>:	mov    rax,QWORD PTR [rip+0xc9509]        # 0x7ffff7c2ae70
   0x00007ffff7b61967 <+151>:	mov    DWORD PTR fs:[rax],0x0
   0x00007ffff7b6196e <+158>:	mov    rax,QWORD PTR [rsp+0x8]
   0x00007ffff7b61973 <+163>:	jmp    0x7ffff7b61942 <ptrace+114>
   0x00007ffff7b61975 <+165>:	nop    DWORD PTR [rax]
   0x00007ffff7b61978 <+168>:	mov    rdx,QWORD PTR [rip+0xc94f1]        # 0x7ffff7c2ae70
   0x00007ffff7b6197f <+175>:	neg    eax
   0x00007ffff7b61981 <+177>:	mov    DWORD PTR fs:[rdx],eax
   0x00007ffff7b61984 <+180>:	mov    rax,0xffffffffffffffff
   0x00007ffff7b6198b <+187>:	jmp    0x7ffff7b61942 <ptrace+114>
   0x00007ffff7b6198d <+189>:	call   0x7ffff7b7a7b0 <__stack_chk_fail>
End of assembler dump.
```
Above the syscall at +93, 0x65 is moved into EAX. This is the number associated with ptrace(rather 101d), [see me for more](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/). We know ptrace can only be run once on a process and that debuggers will almost always call it, so this is how the program can detect our debugger.
```
$ man ptrace
RETURN VALUE
       On success, the PTRACE_PEEK* requests return the requested data (but see NOTES), the PTRACE_SECCOMP_GET_FILTER request returns the number of instructions in the BPF program, and other requests return zero.

       On error, all requests return -1, and errno is set appropriately.  Since the value returned by a successful PTRACE_PEEK* request may be -1, the caller must clear errno before the call, and then check it afterward to determine whether or  not  an  error  occurred.
```
As the man page shows, ptrace returns -1 on error, from there its pretty obvious the program will exit or mislead us. Whatever happens from now on isn't reliable. This is super important to keep in mind when reversing, once you're found out you need to restart, or even in some scenarios such as malware reversal, reset your VM. There isn't a great way to stop ptrace here other than using another debugger or patching the binary(ideally we would buffer overflow and mess with the GOT, but with this binary there is no opportunity), from now I will just change RAX(where the exit code is stored) each time to 0. Jumping over functions is risky, memory could be changed, other things could happen, this isn't strictly an "anti debugger function".

P.S 
1. We could have found all this out by stepping into the call, GDB does most of the heavy lifting for us, but its nice to know how it works. 
2. Another way of finding the address would be to use objdump -d to view the PLT like that.
3. This binary uses another noobproofing method after this, if you read everything I wrote you'll know whats going on)

**3. Time**
After seeing how easily a function can be wrapped as another-- just by changing the address it points to in the GOT, we have learned are lesson and are never ever going to blindly next over a call function again, stepping in then using "fin" to exit out is always a safer option.
Because of that, we immediately know whats going on when we see 
```
 0x555555556004    call   exit@plt <0x555555555030>
        status: 0x555555557100 ◂— 'What is the answer to the Ultimate Question of Life, The Universe and Everything?\n'
```
A *char[] being passed to exit, something is up. After we step in, we see that exit is actually a wrapper for printf.
```
0x7ffff7ac8560 <printf>        sub    rsp, 0xd8
0x7ffff7ac8567 <printf+7>      mov    qword ptr [rsp + 0x28], rsi
0x7ffff7ac856c <printf+12>     mov    qword ptr [rsp + 0x30], rdx
0x7ffff7ac8571 <printf+17>     mov    qword ptr [rsp + 0x38], rcx
0x7ffff7ac8576 <printf+22>     mov    qword ptr [rsp + 0x40], r8
0x7ffff7ac857b <printf+27>     mov    qword ptr [rsp + 0x48], r9
0x7ffff7ac8580 <printf+32>     test   al, al
0x7ffff7ac8582 <printf+34>     je     printf+91 <0x7ffff7ac85bb>
```
Same goes with fork() which is actually puts(). From now on I will replace all the plt calls with their correct names.
```
0x555555555d0c    mov    qword ptr [rbp - 0x68], rdi
0x555555555d10    mov    dword ptr [rbp - 0x6c], esi
0x555555555d13    lea    rax, [rbp - 0x20]
0x555555555d17    mov    rsi, rax
0x555555555d1a    mov    edi, 1
0x555555555d1f    call   clock_gettime  <0x555555555060>
```
Now clock_gettime() is stored in RSI, and eventually, if we keep stepping, we get:
```
pwndbg>
What are you running on? A C64?!
```
This is pretty easy to get around, it looks like its trying to stop is stepping through. Setting a breakpoint after the second call to clock_gettime() then using ```continue``` in gdb will fix this. If you wanted you could set RSI after the first call to some time in the far future, but then you're risking sanity checks.
**4. Path comparison**
```
0x555555555f35    lea    rdx, [rbp - 0x60]
0x555555555f39    mov    rax, qword ptr [rbp - 0x68]
0x555555555f3d    mov    rsi, rdx
0x555555555f40    mov    rdi, rax
0x555555555f43    call   strcmp@plt <0x5555555550d0>
```
This test is comparing two paths together, our current path, and one that was generated in the loop after the last step(hopefully you knew how to set a breakpoint...).
If you want to, you could rename your executable and move it to the root directory--it would actually be a good idea in general incase the path is used as data later. I will just ```set $rax=0``` in gdb after the strcmp(this is actually strcmp, no tricks here)
**5. Time travel**
Our next call is to time, which we then see in stdout
```
Timestamp: 1565888805
```
Looking at the disassembly..
```
00101ca7 c7 45 fc        MOV        dword ptr [RBP + -0x4],0x5d4412d5
         d5 12 44 5d
00101cae bf 00 00        MOV        EDI,0x0
         00 00
00101cb3 e8 38 f4        CALL       time
         ff ff
00101cb8 89 45 f8        MOV        dword ptr [RBP + -0x8],EAX 
00101cbb 8b 45 f8        MOV        EAX,dword ptr [RBP + -0x8] (Silly compiler!)
00101cbe 89 c6           MOV        ESI,EAX
00101cc0 48 8d 3d        LEA        RDI,[s_Timestamp:_%d_00103078]                   = "Timestamp: %d\n"
         b1 13 00 00
00101cc7 b8 00 00        MOV        EAX,0x0
         00 00
00101ccc e8 5f f3        CALL       printf                                             = "Timestamp: %d\n"
         ff ff                                                                       void exit(int __status)
00101cd1 8b 45 fc        MOV        EAX,dword ptr [RBP + -0x4] (Break here and set it equal to [$rbp-0x4])
00101cd4 3b 45 f8        CMP        EAX,dword ptr [RBP + -0x8]
00101cd7 74 0e           JZ         LAB_00101ce7 (Takes us to "Right on time")
00101cd9 48 8d 3d        LEA        RDI,[s_Too_slow!_00103087]                       = "Too slow!"
         a7 13 00 00
00101ce0 e8 8b f3        CALL       puts                                             __pid_t fork(void)
         ff ff
00101ce5 eb 16           JMP        LAB_00101cfd
00101ce7 48 8d 3d        LEA        RDI,[s_Right_on_time._00103091]                  = "Right on time."
         a3 13 00 00
00101cee e8 7d f3        CALL       puts                                             __pid_t puts(void)
         ff ff
00101cf3 8b 45 f8        MOV        EAX,dword ptr [RBP + -0x8]
00101cf6 89 c7           MOV        EDI,EAX
00101cf8 e8 5d ff        CALL       FUN_00101c5a                                     undefined FUN_00101c5a(void)
         ff ff

```
We can see that we are comparing our current time [RBP-0x8] to [RBP-0x4](Hard coded to 0x5d4412d5), which in UNIX time is the 2nd of August. A little annoying, as its now a pain to make a debuggerless solution. Instead, ```set {long*}($rbp-8)=0x1111111111111111``` after eax is moved there at cd1. Remember that $rbp-8 and $rbp-4 are next to each other, so we are just setting them to the same thing. I tried settings [$rbp-8] to [$rbp-4], but GDB insisted on zero extending [$rbp-8] over [$rbp-4], using set {int*}($rbp-8)={int}($rbp-4) should work in theory. As you can see, we want to take the jump at cd7 that takes us to "Right on time". 
```
FUN_00101c5a:
00101c62 89 7d fc        MOV        dword ptr [RBP + -0x4],EDI
00101c65 bf 00 00        MOV        EDI,0x0
     00 00
00101c6a e8 81 f4        CALL       time
         ff ff
00101c6f 39 45 fc        CMP        dword ptr [RBP + -0x4],EAX
00101c72 75 0e           JNZ        LAB_00101c82
00101c74 48 8d 3d        LEA        RDI,[s_Your_clock_is_broken._0010303b]           = "Your clock is broken."
         c0 13 00 00
00101c7b e8 f0 f3        CALL       fork                                             __pid_t fork(void)
         ff ff
00101c80 eb 16           JMP        LAB_00101c98
```
Now that we are in the next function, we can see EDI being moved to [RBP-0x4]. If we look back at the previous function above, we can see that the result of the first time() function(the output of which we overwrote) makes its way to EDI. Now it should be pretty clear what the function is doing, its making sure that the time has changed since last time it checked. This is catching people out who maybe tried using their own library to handle time(This would still be reasonably easy to handle).
Now we get
```
377, 610, 987, 1597, 2584, 4181
```
Most likely important later.(spoiler it wasnt)
And another loop function. You can safely break at image base + 0xba5
(You will notice the dev noobs himself here and writes the flag 1000 times to the stack, we'll carry on anyway)
The next call is to socket(). 
Looking at the man page for socket,
```
int socket(int domain, int type, int protocol);
```
Here I made a mistake and completely ignored the inputs to this. Numerical values for enums in C are usually really hard to find, and they can be platform specific. The connection in this case is actually UDP, so bear that in mind. In the future, I will stick to checking both TCP and UDP when looking for outputs.

Also notice 
```
00101bb9 89 45 ec        MOV        dword ptr [RBP + -0x14],EAX
00101bbc 83 7d ec 00     CMP        dword ptr [RBP + -0x14],0x0
00101bc0 0f 88 8d        JS         *dead*
```
Most likely a noob trap, if you had a problem with this, you skipped something.
Also we have
```
0x555555555bc6    lea    rax, [rbp - 0x110]
0x555555555bcd    mov    edx, 0x10
0x555555555bd2    mov    esi, 0
0x555555555bd7    mov    rdi, rax
0x555555555bda    call   memset
```
If you aren't familiar with memset(), RDI is the pointer to the first address of memory to be set, RDX is the amount of bytes that will be written, and RSI is the character to repeat. So in this case, $rbp-0x110 will be set to 16d 0x00's. This isn't massively important here but its good to know.

(Theres alot of moving arguments about here--so either disassemble for yourself or take my word for it)
The input to the ntohs() call afterwards tells us that we're going to be listening on port 0x1a6d imminently. Output of it isn't important to us, basically just changes the endianness of a 2 byte value(I guess make sure you look at the port before and not after the call) 
The input to inet_pton(), "127.0.0.1", tells us we're sending the data over our loopback.

Now we have the sendto() call. The inputs here aren't massively important, we already have everything we need to know.

Now its pretty clear that we just need to listen on port 6765 and we'll get our flag.
```
root@kali:~# nc -l -u -p 6765
CT19{REdLine} || CT19{REdLine} CT19{REdLine} || CT19{REdLine}  CT19{REdLine} || CT19{REdLine} CT19{REdLine} || CT19{REdLine} CT19{REdLine} || CT19{REdLine} CT19{REdLine} || CT19{REdLine}
```
Alot more to it than binary1.

