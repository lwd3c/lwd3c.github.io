+++
title = 'Pwnable.tw - CAOV'
date = 2026-09-21T14:53:35+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## CAOV

`nc chall.pwnable.tw 10306`

Đề bài: *"What does CAOV stand for?"* - câu trả lời nằm trong chính flag.

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/CAOV/caov_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
```

Bài cho kèm cả source `caov.cpp`. libc là glibc 2.23 → không tcache, không safe-linking, không tcache double-free key. Chỉ có fastbin. Full RELRO nên đích cuối phải là hook trong libc chứ không phải GOT.

Binary là C++ build trên libstdc++/libgcc của Ubuntu 16.04 nên không chạy được trên glibc 2.39 của máy; mọi thao tác động và verify local làm trong container Ubuntu 16.04 (glibc 2.23), điều khiển từ pwntools trên host qua `docker exec`.

#### Bug - Copy Assignment Operator Vulnerability

`Data::operator=` khai báo trả về `Data` **theo giá trị** nhưng thân hàm **không có `return`**:

```cpp
Data operator=(const Data &rhs)   // trả Data by value, nhưng không return!
{
    key = new char[strlen(rhs.key)+1];
    strcpy(key, rhs.key);
    ...
}
```

Với một lớp có destructor non-trivial, ABI x86-64 SysV trả object kiểu này qua một **con trỏ ẩn** - một biến tạm trên stack do caller cấp, gọi là return slot. Vì `operator=` không bao giờ ghi vào slot đó, compiler vẫn phát sinh `~Data()` trên nó ở cuối biểu thức `old = *D;` - tức là huỷ một `Data` mà trường `key` chưa bao giờ được khởi tạo.

Decompile `edit()` (`0x4014b0`) thấy rõ:

```c
FUN_0040198e(local_88);                          // Data() trên old
FUN_00401a4c(local_58, local_88, DAT_006032a0);  // old.operator=(*D), retslot = local_58
FUN_00401e6a(local_58);                           // ~Data() gọi trên retslot!
```

`~Data` (`0x401e6a`) là `if (*p) delete[] *p;`, tức `free(*(local_58))`.

`set_name()` được gọi ngay trước `edit()` từ cùng một case trong `playground()`, cùng độ sâu stack, và ghi input của ta vào buffer `tmp[160]` của chính nó. Frame của nó nằm đúng chồng lên frame của `edit()`, nên **qword `key` của retslot đọc từ input name tại offset 96**. Xác nhận động:

```text
Breakpoint ~Data():
  RDI (retslot) = 0x7fff...cdf0
  0x7fff...cdf0: 0xdeadbeefdeadbeef        <- marker của ta, từ name[96..103]
SIGSEGV: __GI___libc_free (mem=0xdeadbeefdeadbeef) at malloc.c:2949
   #1 Data::~Data  #2 edit()  #3 playground()  #4 main()
```

**Primitive**: mỗi lần `2. Edit name & data` là một lần `free(name[96..103])` - arbitrary free, hoàn toàn điều khiển, lặp lại được.

Lặp được vì giới hạn 10 lần edit chỉ tăng `change_count` khi độ dài key mới hợp lệ (1..1000); trả lời `New key length: 0` là bỏ qua giới hạn mà lần free vẫn chạy.

Hai cái bẫy về cấu trúc:

- **Alignment**: `free()` từ chối con trỏ không align 16 byte, nên mọi user pointer của fake chunk trong `name` phải kết thúc bằng `?0`.
- **`free(D)` làm hỏng `D->key`**: `_int_free` ghi đầu fastbin vào `chunk+0x10`, mà với object `Data` global thì đó đúng là trường `key` (offset 0). Bin rỗng thì ghi 0, và `strlen(D->key)` kế tiếp fault. Cách sửa: mồi sẵn fastbin tương ứng trước khi free `D`.

### 2. Khai thác

`sizeof(Data) = 0x30` nên object là chunk 0x40. Hằng số: `name = 0x6032c0`, `D = 0x6032a0`, `strlen@GOT = 0x602f68`.

#### Leak heap

`operator=` còn làm `key = new char[strlen(rhs.key)+1]; strcpy(key, rhs.key)` - vừa cấp phát vừa ghi nội dung theo ý ta, và `edit_data` thì `D->key = new char[new_len+1]`.

- Free một fake chunk 0x30 tại header `name` (user `name+0x10`); lần `key = new char[33]` kế tiếp trả về đúng địa chỉ **bss** đó → `D->key = name+0x10`
- Rồi free một fake chunk **0x20** tại cùng chỗ. `fd` của nó là chunk heap thật mà `~Data(old)` đã free ở cuối lần edit trước (`old.key`). `D->info()` giờ in ra `D->key` chính là con trỏ heap đó
- Delta đo được: `old.key == D + 0x70` (local gdb)

#### Leak libc

Free `D`, rồi để lần realloc trong cùng lần edit đó trả về chunk của `D`, và `getline` ghi đè toàn bộ struct `Data`, đặt `D->key = strlen@GOT`. Hàm in của object trả về địa chỉ libc đã resolve của `strlen`:

```js
strlen leak = 0x7f...b70  ->  libc base = leak - 0x8ab70   (page-aligned)
```

#### Fastbin poison → `__malloc_hook = one_gadget`

Fake chunk 0x70 `V = name+0x20` (header `name+0x10`, size `name[0x18]=0x71`, size chunk kế `name[0x88]=0x71`). `malloc(0x70)` map được về `__malloc_hook-0x23` vì qword nằm 8 byte vào trong đó là `0x76` - một size fastbin hợp lệ cho bin 0x70 - và glibc 2.23 không kiểm tra gì thêm. `free(NULL)` là no-op (destructor của retslot có `if (*p)`), nhờ vậy một chu kỳ có thể không động tới bin.

- **A**: free `V` → `fastbin[0x70] = V`
- **B**: `set_name` ghi lại `V->fd = __malloc_hook-0x23`, lần free là NULL
- **C**: `new_len=0x60` → `new char[0x61]` pop `V`, head thành hook
- **D**: `new_len=0x60` → pop fake hook chunk, `malloc` trả về `__malloc_hook-0x13`, `getline` ghi `b'A'*0x13 + p64(one_gadget)`

Trigger: bất kỳ `malloc` nào sau đó gọi `__malloc_hook`, one_gadget `0xef6c4` = `execve("/bin/sh", rsp+0x50, environ)`.

#### Hai cái bẫy môi trường

**Dữ liệu timezone hỏng.** Container (và cả server) có symlink `/usr/share/zoneinfo` treo, nên `localtime()` trong `update_time()` fail ở `fopen("/etc/localtime")` và phần dọn dẹp của glibc chạy `free`/`malloc` mỗi lần gọi.

- Ở local, lần `free` dọn dẹp đó chạy `malloc_consolidate` lên các fake fastbin chunk của ta → SIGABRT. Sửa cho lab bằng `TZ=UTC` (không đụng file I/O)
- Nó cũng làm lệch layout heap lúc đầu, giải thích vì sao delta object là `0x70` ở local nhưng `0x90` trên server (tìm ra bằng cách quét các delta ứng viên trên server)

**Hook kích hoạt sớm trên server.** Vì `localtime()` malloc mỗi lần gọi, one_gadget được gọi *bên trong* `update_time()` ngay sau khi `getline` của chu kỳ D set `__malloc_hook` - trước khi bất kỳ prompt menu nào trả về. Chờ `Your choice:` là deadlock. Sửa: ở chu kỳ D gửi luôn lệnh shell ngay sau phần nhập `Value`, shell vừa spawn sẽ đọc chúng.

```bash
heap leak = 0x815cb0  ->  D = 0x815c20
strlen leak = 0x7fd1cbb1fb70  ->  libc base = 0x7fd1cba95000
shell check: b'BEGIN\nuid=1000(caov) gid=1000(caov) groups=1000(caov)\nEND\n'
FLAG{CAOV_stands_f0r_C0py_Ass1gnment_Operat0r_Vuln3rabil1ty_r3memb3r_alway5_r3turn_r3ference_typ3}
```

`FLAG: FLAG{CAOV_stands_f0r_C0py_Ass1gnment_Operat0r_Vuln3rabil1ty_r3memb3r_alway5_r3turn_r3ference_typ3}`

```py
NAME = 0x6032c0
GOT_STRLEN = 0x602f68

# Stage 1: D->key = name+0x10 (free fake chunk 0x30 tại header `name`)
# Stage 3: leak heap: free fake chunk 0x20 tại `name`; fd của nó = old.key
heap_leak = leak_parse(edit(...))
D = heap_leak - (0x90 if args.REMOTE else 0x70)

# Stage 4: mồi fastbin[0x40] để free(D) vẫn để D->key đọc được
# Stage 2: free D, realloc D, D->key = strlen@GOT  -> leak libc
libc_base = leak - libc.sym['strlen']

V, T = NAME+0x20, libc_base + libc.sym['__malloc_hook'] - 0x23
og   = libc_base + 0xef6c4

# fastbin poison: V->fd = T, pop V, pop T, ghi __malloc_hook = og
# rồi gửi input menu / lệnh shell; uid=1000(caov)
```
