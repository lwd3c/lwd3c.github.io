+++
title = 'Pwnable.tw - BookWriter'
date = 2026-09-21T14:53:01+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## BookWriter

`nc chall.pwnable.tw 10304`

Tác giả bài có để lại hint: *"I fixed some bug of memo from bkp CTF 2017 and modified some control flow, but it's still pwnable"*.

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/BookWriter/bookwriter_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
FORTIFY:    Enabled
```

`.comment` cho thấy `GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0` - build thời Ubuntu 16.04, khớp với một bài khoảng 2016/2017. libc đi kèm glibc 2.23 (có debug_info, không stripped).

Full RELRO loại hết đường GOT overwrite. Canary có nhưng không dùng tới. No PIE cố định địa chỉ của binary, nhưng libc và heap vẫn ASLR nên vẫn cần leak.

Menu: `1. Add a page`, `2. View a page`, `3. Edit a page`, `4. Information`, `5. Exit`.

Phân tích tĩnh bằng `r2 -qc "aaa; pdf @ <fcn>"` (Ghidra MCP và IDA MCP đều không kết nối được phiên đó), đối chiếu từng nhánh với byte thô thay vì tin pseudocode - mà pseudocode dịch sai ít nhất một phép so sánh signed/unsigned.

Ba điều quan trọng:

- **Binary không import `free()` ở bất cứ đâu.** Không có option Delete; "Information" chiếm đúng cái slot menu mà một option Delete thường nằm. Riêng điều này loại sạch mọi kỹ thuật fastbin/tcache/UAF/double-free.
- Bug kinh điển của BookWriter - ghi tên tác giả quá cỡ tràn sang mảng con trỏ page - **đã được vá**: buffer author đúng `0x40` byte và lời gọi read truyền đúng `esi=0x40`.
- Vòng tìm slot trống của `Add` có **off-by-one**.

#### Bug 1 - buffer không NUL-terminate → leak

Hàm read dùng chung (`fcn.00400856`) chỉ thêm NUL khi **byte cuối đọc được là `'\n'`** - ngược lại buffer để nguyên, không kết thúc. Gửi đúng 64 byte cho tên tác giả (không newline) là nó không terminate, rồi `printf("Author : %s\n", author_buf)` của `Information` đi thẳng sang mảng `book_ptr[]` kế bên.

```text
=== LEAKED bytes beyond our own 64-byte author ===
b'\x10\xf0\x95\x13\n...'
diễn giải thành pointer: 0x...1395f010   <- khớp đúng book_ptr[0]
```

#### Bug 2 - off-by-one trong vòng tìm slot của `Add`

```asm
0x400a82: cmp dword [idx], 8
          jbe 0x4009c6     ; BUG: idx <= 8, lẽ ra <= 7 (View/Edit đều dùng đúng 7)
```

`book_ptr[8]` trùng địa chỉ của chính `book_size[0]`; lần `Add` thứ 9 (đến được khi size của page 0 bằng 0, nên alias đọc ra "trống") ghi đè `book_size[0]` bằng một con trỏ heap thô. Xác nhận trong gdb: sau lần add thứ 9, `x/2gx 0x6020e0` cho thấy `book_size[0]` giữ đúng địa chỉ chunk thứ 9.

#### Bug 3 - size tự phình → House of Orange không cần `free()`

Vẫn là cái quirk "không newline nên không NUL", lần này áp lên chính phép cập nhật `book_size[idx] = strlen(book_ptr[idx])` của `Edit`: sửa một page với nội dung lấp đầy đúng chunk của nó (không newline) làm `strlen()` quét **vượt qua** chunk sang header chunk kế tiếp, âm thầm tăng size đã đăng ký cho lần edit *sau* của slot đó thêm đúng số byte khác 0 nằm ngay sau.

Phần tăng thêm đó vừa đủ để ghi đè trường size của **top chunk thật** bằng một giá trị giả nhỏ. Lần `Add` kế tiếp với size yêu cầu lớn hơn giá trị giả đó buộc chính `sysmalloc()` của glibc gộp cái top (giả nhỏ) cũ vào unsorted bin - một lần free mà không có `free()`, tức **House of Orange** kinh điển, đạt được trong một binary hoàn toàn không có đường free nào.

Một lần `Add` nhỏ nữa cắt phần remainder đã free; `bk` còn sót của nó vẫn link vào `main_arena`, cho ta leak libc.

### 2. Khai thác

1. **Leak heap** - tên tác giả 64 byte không terminate + một lần `Add`
2. **House of Orange** - tự phình size của page thứ hai, giả size top chunk, ép `sysmalloc()` consolidate, leak `libc_base` từ remainder đã free
3. **FSOP** - lấp nốt các slot còn lại, kích hoạt lần `Add` thứ 9 của off-by-one, dùng `Edit(0)` giờ đã khổng lồ để ghi một payload dựng cặp `_IO_FILE` + vtable tại địa chỉ (giờ đã biết) của remainder unsorted bin: `bk → _IO_list_all - offset` (unsorted bin attack), slot finish/overflow của vtable trỏ `system`, và mấy byte đầu của fake FILE kiêm luôn tham số `"/bin/sh"`
4. Một lần `Add` cuối kích hoạt đường flush stream qua `_IO_list_all` → `system("/bin/sh")`

#### Các giá trị đo được

| Giá trị | Cách lấy |
|---|---|
| Heap base | leak đọc lố buffer author, đối chiếu `x/gx` trong gdb, khớp đúng |
| Phần dư non-NUL của top `k` | đo trực tiếp mỗi lần chạy bằng một lần `View` không terminate, `k=3` ổn định qua mọi lần |
| `libc_base` | `leak - 0x3c4188` từ `bk` của remainder top đã free, đối chiếu `vmmap` trong gdb, khớp đúng |
| `_IO_list_all`, `system` | `libc.sym[...]` trên libc đi kèm không stripped |

Chạy local 4 lần độc lập đều pass. Địa chỉ heap/libc khác nhau mỗi lần do ASLR nhưng `k=3` và cơ chế khai thác giống hệt - đây là exploit tất định với đúng bản binary/libc này, không phải xác suất.

```bash
[*] heap base = 0x13e4000
[*] top-size non-NUL prefix k = 3
[*] libc base = 0x7f17d66b1000
uid=1000(bookwriter) gid=1000(bookwriter) groups=1000(bookwriter)
FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}
```

`FLAG: FLAG{Th3r3_4r3_S0m3_m4gic_in_t0p}`

Điểm đáng nhớ nhất: **không import `free()` không có nghĩa là mọi kỹ thuật unsorted-bin/consolidation đều vô dụng** - đường top-chunk-too-small của chính `sysmalloc()` làm thay việc của `free`. Và một quirk duy nhất của hàm read ("không newline thì không NUL") đẻ ra hai bug độc lập: leak địa chỉ heap, và tự phình size.
