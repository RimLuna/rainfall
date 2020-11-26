# rainfall
Kill me, I'm getting kicked 
```
level0@RainFall:~$ ./level0 
Segmentation fault (core dumped)
```
*wtf fucking kill me, I give up*
```
level0@RainFall:~$ file level0 
level0: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0x85cf4024dbe79c7ccf4f30e7c601a356ce04f412, not stripped
```
*yay not stripped*
```
level0@RainFall:~$ ls -al
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
```
*nice, the SUID perm again*

Using **binary ninja**, found that the executable calls execve("/bin/sh")
```
mov     dword [esp], data_80c5348  {"/bin/sh"}
call    execv
```
## ROP ( Return-oriented programming) ecploit
Googled it, although I've done pwning before but still can't fucking explain anything

**The main idea is to use the existing small fragments in the program based on the stack buffer overflow. ) to change the value of some registers or variables to control the execution flow of the program.**

It's called ROP because we use the **ret** instruction to change the order in which the instruction stream is executed.

### What the fuck am I doing

```
level0@RainFall:~$ checksec --file level0 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   level0
```
*NX is enabled, meaning you can't use shellcode or put anything on the stack in order to execute it.*

