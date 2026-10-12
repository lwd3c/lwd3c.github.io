+++
title = 'Pwnable.tw - Break Out'
date = 2026-09-24T10:42:40+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Break Out

`nc chall.pwnable.tw 10400`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Break Out/breakout_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
Stripped:   No
```

Binary C++ (dùng `libstdc++`, `__cxa_*`), libc đi kèm glibc 2.23. Kèm theo còn file `prisoner` - một "database" phẳng 10 tù nhân dạng `name:alias:age:sentence`, được nạp lúc khởi động.

`init()` mở `prisoner`, mỗi dòng `calloc(1, 0x40)` ra một chunk 0x50 làm struct tù nhân:

```js
+0x00  vtable (trỏ tới chuỗi "High")
+0x08  name      (asprintf)
+0x10  alias     (asprintf)
+0x18  age       (dword)
+0x1c  id        (dword, 0-based)
+0x20  sentence  (asprintf)
+0x28  note_size (dword)
+0x30  note_ptr
+0x38  next
```

`head` là node parse **cuối cùng** nên `list()` duyệt ngược.

- `note()`: đọc `cell` id và `size`, tìm struct theo id, rồi
  `if (note_size < size && note_size) realloc(note_ptr, size); else if (!note_size) malloc(size);`
  **còn lại thì ghi thẳng `size` bytes vào `note_ptr` hiện có** mà không đổi `note_size`.
- `punish()`: nếu `occupied` thì từ chối; không thì `free(struct)` **mà không gỡ khỏi linked list**, rồi set `occupied = 1`.
- `list()`: in các trường bằng `printf("%s")` cộng một `write(1, note_ptr, note_size)` thô.
- `secure_read(dst, n)`: chỉ cho ghi trong `[heap_start, heap_end]` hoặc `[heap+0x8c0, heap+0xa10]`, parse từ `/proc/self/maps` bởi `secure_self`. **Ghi ngoài heap bị chặn** - nên không GOT, không `__free_hook`, đích FSOP phải nằm trong libc.

#### Bug 1 - UAF mà node vẫn còn trong list

`punish(0)` free struct của tù nhân #0 nhưng để nó vẫn nằm trong linked list, con trỏ dangling vẫn dùng được. Chunk 0x50 vừa free rơi vào `fastbin[0x50]`; một lần `note(1, 0x40, ...)` sau đó (`note_size == 0` → `malloc`) lấy lại đúng chunk ấy làm note buffer của cell #1. Ghi vào note của cell 1 là **ghi đè các trường struct của tù nhân #0**.

#### Bug 2 - short write sửa một phần con trỏ

`note(1, 0x40, payload)` rơi vào nhánh `size <= note_size`, ghi đúng `payload` vào `note_ptr` mà không realloc. Gửi `p64(0) + p16(g)` là zero vtable và chỉ ghi đè **16 bit thấp của con trỏ `name`**, giữ nguyên phần page heap ở trên - thành một cửa sổ đọc trượt 64 KB qua `%s` của `list()`.

#### Vì sao remote fail lúc đầu

Lần chạy local đầu dùng một build glibc 2.23 khác (snap core) nên offset bin và nhất là layout heap không khớp server. Sửa bằng cách chạy với đúng `libc_64.so.6` và loader đi kèm (`breakout_patched`, interp `./ld-2.23.so`, RUNPATH `.`).

Nguyên nhân thứ hai tinh vi hơn: reader dựa trên `%s` nên trả về **chuỗi rỗng với mọi con trỏ có byte thấp bằng `0x00`** (khoảng 1/16). Biểu hiện là lỗi `A read NUL` lúc được lúc không. Sửa bằng cách khi đọc rỗng thì đọc lại lệch một byte rồi dịch trái 8 để dựng lại giá trị.

Layout đo trực tiếp qua `/proc/<pid>/mem` và pwndbg:

| giá trị | offset |
|---|---|
| struct tù nhân #0 | `heap + 0x11c20` |
| chuỗi `sentence` của nó | `heap + 0x11d20` |
| chunk 0xb0 đã free C | `heap + 0x12440`, `fd = bk = libc + 0x3c3b78` (unsorted) / `0x3c3c18` (smallbin) |
| chỉ số cửa sổ | `g(off) = g_leak + (off - 0x12440)` |

libc đi kèm: `_IO_list_all = 0x3c4520`, `system = 0x45390`.

### 2. Khai thác

1. **Leak libc.** Free một chunk lớn hơn tầm fastbin (`note(2,0xa0)` rồi một guard rồi `note(2,0xb0)` để dời nó) để chunk 0xb0 cũ rơi vào unsorted/smallbin; quét cửa sổ ứng viên `g` và đọc `fd` → `libc_base = leak - {0x3c3b78 | 0x3c3c18}`, assert page-aligned.

2. **Leak heap.** Đọc `struct0.sentence` qua cửa sổ → `heap_base = value - 0x11d20`.

3. **Ghi tuỳ ý.** `note(1, 0x550, ...)` làm realloc dời note của cell 1, giải phóng struct0 vào `fastbin[0x50]`; `note(4, 0x40, craft)` lấy nó về cell 4 và ghi `craft`, biến struct0 thành cell 0 với `note_size = len`, `note_ptr = target`; `note(0, len, data)` short-write vào `target`. Mỗi lần ghi đều đọc lại để xác nhận.

4. **Largebin attack → FSOP.**
   - `A = note(5, 0x510)` (chunk 0x520) kèm guard in-use phía sau; `W = note(7, 0x520)` (chunk 0x530) kèm guard; nhớ `A_abs`, `W_abs`
   - Free A (`note(5, 0x530)`) → unsorted; `note(9, 0x528)` malloc và đẩy A vào largebin 68
   - `arb_write(A_abs+0x18, p64(_IO_list_all - 0x20))` đầu độc `A->bk_nextsize`
   - Đắp `_IO_FILE` giả **bên trong W vẫn đang allocated** bằng short write (`note(7, 0x220, ...)`): `_mode=0`, `_IO_write_ptr > _IO_write_base`, `_chain=NULL`, `vtable = W_abs+0x200`, và `system` tại `vtable + 0x18` (`__overflow`)
   - `note(7, 0x530, ...)` làm realloc dời W, giải phóng chunk W **cũ** với nguyên vẹn các byte FILE
   - `arb_write(W_abs-0x10, "/bin/sh\0")` - đích của `_IO_list_all` chính là header chunk của W
   - `note(3, 0x529)` đẩy W vào largebin 68: glibc chạy `victim->bk_nextsize->fd_nextsize = victim`, ghi **địa chỉ chunk của W** vào `_IO_list_all`
   - `note 999` → `abort()` → `_IO_flush_all_lockp` → `_IO_OVERFLOW(fp, EOF)` → `system("/bin/sh")`, vì glibc 2.23 không validate vtable

```bash
[*] hb=0x563e97717000 libc=0x7f79c8023000
[+] _IO_list_all overwritten -> firing abort
[+] REMOTE: FLAG{Br3ak_0ut_7He_Pr1s0N}
```

`FLAG: FLAG{Br3ak_0ut_7He_Pr1s0N}`

Một điểm đáng nhớ: `realloc` khi dời chunk là copy rồi free, nên chunk cũ vừa giải phóng vẫn giữ nguyên nội dung. Nhờ vậy `_IO_FILE` giả ghi bằng short write (không dời) sống sót qua lần free - nhưng phải lấy địa chỉ nạn nhân **trước** khi dời, và nhớ rằng thao tác binning sẽ đè `0x20` byte user đầu tiên.
