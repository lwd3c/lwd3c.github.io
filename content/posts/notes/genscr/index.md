+++
title = 'Generation Script Exploit Pwn'
date = 2026-02-15T17:44:04+07:00
draft = false
categories = ["notes"]
+++

## 1. Genscr AMD

```python
#!/usr/bin/python3

import sys
import os

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} BIN [LIBC] [HOST] [PORT]")
    print(f"Examples:")
    print(f"  {sys.argv[0]} ./chall")
    print(f"  {sys.argv[0]} ./chall ./libc.so.6")
    print(f"  {sys.argv[0]} ./chall mercury.picoctf.net 33411")
    print(f"  {sys.argv[0]} ./chall ./libc.so.6 mercury.picoctf.net 33411")
    exit(1)

bin_path = sys.argv[1]
libc_path = None
host = ""
port = "0"

if len(sys.argv) >= 5 and os.path.isfile(sys.argv[2]):
    libc_path = sys.argv[2]
    host = sys.argv[3]
    port = sys.argv[4]

elif len(sys.argv) >= 4 and not os.path.isfile(sys.argv[2]):
    host = sys.argv[2]
    port = sys.argv[3]

elif len(sys.argv) >= 3 and os.path.isfile(sys.argv[2]):
    libc_path = sys.argv[2]

libc_line = f"libc = ELF('{libc_path}', checksec=False)" if libc_path else "# libc = ELF('', checksec=False)"
remote_line = f'p = remote("{host}", int("{port}"))' if host and port else 'p = remote(" ", " ")'

script = f'''#!/usr/bin/env python3

from pwn import *

exe = ELF('{bin_path}', checksec=False)
{libc_line}
context.binary = exe

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
ra     = lambda proc=None: proc.recvall() if proc else p.recvall()

def GDB():
    gdb.attach(p, gdbscript=\"\"\"


        \"\"\")

if args.REMOTE:
    {remote_line}
else:
    p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !



p.interactive()
'''

filename = 'exploit.py'
should_write = True

if os.path.exists(filename):
    ans = input(f"[!] File '{filename}' already exists. Overwrite? (y/n): ").strip().lower()
    if ans.lower() != 'y':
        print("[*] Keeping existing file. Abort write.")
        should_write = False

if should_write:
    with open(filename, 'wt') as f:
        f.write(script)
    os.chmod(filename, 0o755)
    print(f"[+] Wrote {filename}")
else:
    print("[*] Skipped writing file.")

os.system(f'chmod +x {bin_path}')

if libc_path:
    os.system(f'chmod +x {libc_path}')

os.system(f'code . {filename}')

```
Sau đó copy file này vào /usr/local/bin và chmod+x là có thể sử dụng!


## 2. Genscr AMD + ARM

```py
#!/usr/bin/env python3
import sys, os
from pwn import ELF

if len(sys.argv) <= 1:
    print(f"Usage: {sys.argv[0]} BIN [LIBC] [HOST] [PORT]")
    print(f"Examples:")
    print(f"  {sys.argv[0]} ./chall")
    print(f"  {sys.argv[0]} ./chall ./libc.so.6")
    print(f"  {sys.argv[0]} ./chall mercury.picoctf.net 33411")
    print(f"  {sys.argv[0]} ./chall ./libc.so.6 mercury.picoctf.net 33411")
    exit(1)

bin_path = sys.argv[1]
libc_path = None
host, port = "", "0"

if len(sys.argv) >= 5 and os.path.isfile(sys.argv[2]):
    libc_path = sys.argv[2]
    host, port = sys.argv[3], sys.argv[4]
elif len(sys.argv) >= 4 and not os.path.isfile(sys.argv[2]):
    host, port = sys.argv[2], sys.argv[3]
elif len(sys.argv) >= 3 and os.path.isfile(sys.argv[2]):
    libc_path = sys.argv[2]

# Detect architecture
try:
    e = ELF(bin_path)
    arch = e.arch
except:
    arch = "unknown"

libc_line = f"libc = ELF('{libc_path}', checksec=False)" if libc_path else "# libc = ELF('', checksec=False)"
remote_line = f'p = remote("{host}", int("{port}"))' if host and port else 'p = remote("", "")'

# Select emulator if needed
emu_line = ""
emu_gdb_setup = ""

if "arm" in arch:
    if "aarch64" in arch or "ARM64" in arch:
        emu_line = 'qemu_bin = "qemu-aarch64"\n    qemu_args = ["-L", "/usr/aarch64-linux-gnu"]'
        emu_gdb_setup = "set architecture aarch64"
        arch = "aarch64"
    else:
        emu_line = 'qemu_bin = "qemu-arm"\n    qemu_args = ["-L", "/usr/arm-linux-gnueabi"]'
        emu_gdb_setup = "set architecture arm"
        arch = "arm"
else:
    # native x86 or x64
    emu_line = 'qemu_bin = None'
    emu_gdb_setup = ""

script = f"""#!/usr/bin/env python3
from pwn import *

exe = ELF('{bin_path}', checksec=False)
{libc_line}

context.binary = exe
context.os = 'linux'
context.arch = '{arch}'
context.endian = 'little'

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
ra     = lambda proc=None: proc.recvall() if proc else p.recvall()

def GDB():
    gdb.attach(p, gdbscript=\"\"\"
        {emu_gdb_setup}
        
    \"\"\")

if args.REMOTE:
    {remote_line}
else:
    {emu_line}
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !



p.interactive()
"""

filename = "exploit.py"
if os.path.exists(filename):
    ans = input(f"[!] File '{filename}' already exists. Overwrite? (y/n): ").strip().lower()
    if ans != "y":
        print("[*] Keeping existing file. Abort write.")
        exit(0)

with open(filename, "wt") as f:
    f.write(script)
os.chmod(filename, 0o755)
print(f"[+] Wrote {filename}")

os.system(f"chmod +x {bin_path}")
if libc_path:
    os.system(f"chmod +x {libc_path}")
os.system(f"code . {filename}")
```