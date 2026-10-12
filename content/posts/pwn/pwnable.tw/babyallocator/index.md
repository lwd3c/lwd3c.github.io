+++
title = 'Pwnable.tw - BabyAllocator'
date = 2026-09-28T19:51:30+07:00
draft = true
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## BabyAllocator

`nc chall.pwnable.tw 10404`

> Bài này **chưa giải xong**. Dưới đây là ghi chép phân tích tĩnh đã làm, các hướng đã loại và giả thuyết đang theo.

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/BabyAllocator/babyallocator
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

Binary stripped, libc glibc 2.23 → không tcache, không safe-linking, `__malloc_hook`/`__free_hook` vẫn sống.

Import đáng chú ý: `free`, `malloc`, `mprotect`, `mmap`, `read`, `write`, `puts`, `__isoc99_scanf`, `setvbuf`, `alarm`. **Vắng mặt**: `system`, `execve`, `open`, `printf` - chính sự vắng mặt này cũng là tín hiệu. Không có import `prctl`/seccomp.

one_gadget trên libc đi kèm:

```js
0x45216  execve("/bin/sh", rsp+0x30, environ)   ; rax == NULL
0x4526a  execve("/bin/sh", rsp+0x30, environ)   ; [rsp+0x30] == NULL
0xef6c4  execve("/bin/sh", rsp+0x50, environ)   ; [rsp+0x50] == NULL
0xf0567  execve("/bin/sh", rsp+0x70, environ)   ; [rsp+0x70] == NULL
```

#### Binary được build với `-fsplit-stack`

Đây là điểm đặc biệt của bài. `generic-morestack.c` của libgcc được link tĩnh vào. Bằng chứng: các chuỗi `../.././libgcc/generic-morestack.c`, `allocate_segment`, `SPLIT_STACK_GUARD`, `p == 0 || p == pagesize`, `unable to allocate additional stack space: errno `.

Các hàm runtime split-stack nhận diện được:

| addr | tên trong libgcc |
|---|---|
| `0x402617` | `__morestack` (asm) |
| `0x4017d0` | `__generic_morestack` (+ `allocate_segment` inline) |
| `0x401e30` | `__morestack_allocate_stack_space` |
| `0x401510` | `free_dynamic_blocks` |
| `0x401620` | `free_segments` (xref duy nhất: `0x402555`) |
| `0x401cd0` | helper pop segment dùng ở epilogue của `__morestack` |
| `0x401760` | `__generic_morestack_set_initial_sp` |
| `0x40270c` | `__stack_split_initialize` |
| `0x402010` | `__splitstack_find` |

`struct stack_segment` (size 56 = `0x38`), dựng lại từ `munmap(seg, seg->size + 56)`:

```js
+0x00 prev
+0x08 next
+0x10 size
+0x18 old_stack
+0x20 dynamic_allocation        (danh sách block phát cho alloca-on-heap)
+0x28 free_dynamic_allocation   (cache block dùng lại được)
+0x30 extra[]
```

`struct dynamic_allocation_blocks` (`malloc(0x18)`):

```js
+0x00 next
+0x08 size
+0x10 block   <- trả về cho caller làm buffer "alloca"
```

Frame của `menu()`:

```js
rbp-0x30  s[16]        name, scanf("%15s")
rbp-0x20  cur          đích ghi của option 3
rbp-0x18  heap_ptr     malloc bởi option 2, free bởi option 5
rbp-0x10  size
rbp-0x08  stack_buf    kết quả alloca
```

Prologue split-stack của `menu()`: `cmp rsp, fs:0x70 / jae body / mov r10d,0x38 / call __morestack`.

Option 1 (Alloca on stack), codegen tại `0x401325`:

```c
v0 = 16 * ((size + 30) / 16);          // size bị ràng buộc trong [0x80, 0xFFF]
if (rsp - v0 >= fs:0x70) { sub rsp, v0; buf = rsp; }                  // alloca thật
else                     { buf = __morestack_allocate_stack_space(v0+15); }  // HEAP
buf = (buf + 15) & ~15;
```

### 2. Trạng thái hiện tại

Kiểm tra số học size bằng tay: `v0 >= size + 15`, size malloc là `v0 + 15`, malloc trả con trỏ align 16 nên vùng dùng được `>= size + 15 > size`. **Không có tràn tuyến tính ở cả hai nhánh.**

Đã loại:

- Không có off-by-one hay lỗi kiểm tra size trong code của chính challenge
- `free_segments` không với tới được (binary không có exception), nên `free_dynamic` không bao giờ được nạp → không có đường dùng lại dynamic block

Giả thuyết đang theo: bug nằm ở phần **bookkeeping của stack segment** (tương quan giữa guard `fs:0x70` và vùng dự trữ `0x600`), chứ không phải ở danh sách block trên heap. Phần này cần đo động, chưa làm.
