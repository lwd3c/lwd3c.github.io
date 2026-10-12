+++
title = 'Pwnable.tw - Ghost Party'
date = 2026-09-23T21:19:53+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Ghost Party

`nc chall.pwnable.tw 10401`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Ghost Party/ghostparty_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
```

Chương trình C++ quản lý "ghost party". Một `std::vector<Ghost*>` giữ các ghost đã thêm:

| choice | hành động |
|---|---|
| 1 | thêm ghost (chọn loại dẫn xuất) |
| 2 | xem info (`listghost()` rồi `showinfo(idx)`) |
| 3 | "night" - mọi ghost nói |
| 4 | xoá ghost |
| 5 | thoát |

Mười lớp dẫn xuất (`Werewolf`, `Devil`, `Zombie`, `Skull`, `Mummy`, `Dullahan`, `Vampire`, `Yuki`, `Kasa`, `Alan`) đều kế thừa `Ghost`. libc là glibc 2.23, không tcache. Full RELRO nên không ghi GOT được, đích cuối phải là hook trong libc.

#### Bug - thiếu copy constructor

Lớp cơ sở `Ghost` viết đúng: có copy constructor deep-copy `char *name` (`new char[]` + `strcpy`) và destructor giải phóng nó. Cái bẫy nằm ở lớp dẫn xuất.

`Vampire` thêm một con trỏ sở hữu dạng thô và giải phóng nó trong destructor, nhưng **không định nghĩa copy constructor**:

```cpp
class Vampire : public Ghost {
    char *blood;
public:
    void addblood(string com){ blood = new char[com.length()+1];
                               memcpy(blood, com.c_str(), com.length()); }
    ~Vampire(){ delete[] blood; }          // giải phóng blood
    // KHÔNG có copy constructor  <-- bug
};
```

Compiler tự sinh một copy constructor gọi của `Ghost` (deep-copy `name`) rồi **shallow-copy từng thành viên** của `Vampire` - `blood` bị copy nguyên con trỏ: hai object, một buffer.

Chỗ kích hoạt: thêm ghost bằng "Join and hear" (`smalllist` case 3) làm hai việc:

```cpp
ghostlist.push_back(ghost);   // object sống vào vector
speaking(*ghost);             // <-- truyền object dẫn xuất THEO GIÁ TRỊ
```

`speaking<T>(T ghost)` nhận tham số theo giá trị nên dựng một `Vampire` tạm qua copy constructor tự sinh (shallow-copy `blood`), in ra, rồi huỷ object tạm - destructor của nó `delete[] blood`. Buffer đó vẫn đang được object **sống** trong vector trỏ tới:

```js
add Vampire (Join and hear):
    live_vampire.blood ─┐
                        ├──► [ heap buffer ]   (bị temp dtor free)
    temp.blood ─────────┘        ▲
                                 └── live_vampire.blood giờ DANGLING
```

- **Use-after-free**: vampire sống giữ `blood` dangling, `Vampire::ghostinfo` in nó bằng `cout << blood` → primitive đọc sau khi free, trên một chunk mà ta kiểm soát cả kích thước lẫn nội dung.
- **Double free**: `remove()` con vampire đó về sau chạy `~Vampire` lần nữa → `delete[] blood` lần hai.

`Devil`/`Zombie`/`Werewolf` có copy constructor deep-copy đàng hoàng nên an toàn; `Alan` có con trỏ thô nhưng không bao giờ free. `Vampire` là loại duy nhất khai thác được - đúng như flag.

`blood` là `new char[len+1]` với độ dài và nội dung ta chọn. Lấy `len = 0x58` cho ra **chunk 0x70**, trong glibc 2.23 nằm ở `fastbin[0x70]` và không bao giờ coalesce.

### 2. Khai thác

1. **Leak heap** - đọc một `blood` dangling đang ở đầu `fastbin[0x70]`, `fd` của nó là địa chỉ heap.
2. **Leak PIE** - đặt một object `Vampire` mới đè lên chunk `blood` đã free; con trỏ vtable của object (trỏ vào binary) đọc được qua `blood` còn dangling. `binbase = leak - 0x2109d8`.
3. **Leak libc** - biến UAF thành một object mà ta ghi đè trường `name` thành `&read@GOT`, rồi để `listghost()` in `name` (hàm `getname()` không ảo), leak địa chỉ libc của `read`. `libc_base = leak - off(read)`.
4. **Fastbin dup → ghi hook** - double-free một `blood` 0x70, đầu độc `fd` trỏ tới fake chunk tại `__malloc_hook - 0x23`, rồi ghi hook.
5. **RIP** - pivot qua `__realloc_hook` → one_gadget → shell.

#### Vì sao `__malloc_hook - 0x23`

Cần một fake chunk `fastbin[0x70]` mà trường size 8 byte phải thoả `fastbin_index(size) == 5`. Ngay dưới `__malloc_hook` có một con trỏ libc với byte cao là `0x7e`. Đặt fake chunk tại `mh - 0x23` làm byte đó rơi đúng vị trí size (`0x7e & ~0xf = 0x70`), nên `malloc(0x70)` chấp nhận và trả về user data tại `mh - 0x13`.

#### Vì sao phải pivot qua realloc hook

Tại thời điểm `__malloc_hook` kích hoạt, **không** ràng buộc nào trong bốn one_gadget thoả (`[rsp+0x30/0x50/0x70] == NULL`, `rax == NULL`), nên gán thẳng `__malloc_hook = one_gadget` là SIGSEGV. Đã xác nhận bằng cách chạy thử.

Cách sửa là pivot hai hook:

```js
__malloc_hook  = __libc_realloc + 4     ; +4 bỏ qua `push r15 ; push r14`
__realloc_hook = one_gadget
```

`malloc` gọi `__malloc_hook` → vào `__libc_realloc+4`, prologue của nó (`push r13/r12/rbp/rbx ; sub rsp,0x38`) **dịch `rsp`** vừa đủ để ràng buộc `[rsp+0x50] == NULL` thoả; `__libc_realloc` sau đó gọi `__realloc_hook` → one_gadget → `execve("/bin/sh")`. Cả hai hook ghi trong cùng một payload fake chunk.

#### Các giá trị đo được

| giá trị | cách lấy |
|---|---|
| `heap_leak` | `show_blood(0)` trên vampire Join-and-hear đầu tiên → `fd` fastbin |
| `binbase` | `pie_leak - 0x2109d8`, `pie_leak` = vtable đọc qua blood dangling chồng object mới |
| `libc_base` | `libc_leak - libc.sym['read']`, `libc_leak` = `*read@GOT` qua `listghost` in name |
| fake chunk | `libc_base + __malloc_hook - 0x23` |
| RIP | `__malloc_hook = libc_base + __libc_realloc + 4`, `__realloc_hook = libc_base + one_gadget` |

libc local `2.23-0ubuntu11.3`: `read=0xf7350`, `__libc_realloc=0x84710`, `__malloc_hook=0x3c4b10`, one_gadget `0xf03a4`.
libc remote `2.23-0ubuntu5`: `read=0xf6670`, `__libc_realloc=0x83b10`, `__malloc_hook=0x3c3b10`, one_gadget **`0xef6c4`** (gadget `[rsp+0x50]==NULL`, tương ứng đúng với cái thắng ở local).

Số lần "đi bộ" trên `fastbin[0x70]` (bao nhiêu lần cấp `Mummy` trước khi fake chunk được phục vụ) **đo trong gdb** chứ không đếm nhẩm: dừng ở menu, dump `fastbins` sau mỗi lần cấp. Chuỗi thao tác là tất định (fastbin LIFO, không ngẫu nhiên) nên số đếm local chuyển sang remote nguyên vẹn, chỉ địa chỉ tuyệt đối là khác và những cái đó đều leak được.

#### Hai chi tiết khi đọc leak

`name` của `Mummy` đọc bằng `cin >> name`, dừng ở whitespace - nên con trỏ hook ghi qua name không được chứa byte `\x09\x0a\x0b\x0c\x0d\x20`. Exploit kiểm tra mỗi lần thử (`has_ws`) và kết nối lại nếu ASLR cho ra byte xấu.

`listghost` gọi `getname()`/`gettype()` **không ảo**; gửi index ngoài phạm vi (999) sau đó để bỏ qua `showinfo` ảo, nếu không nó deref vtable đã hỏng và crash trước khi exploit xong.

```bash
[*] heap_leak = 0x560e2c5c1dc0   binbase = 0x560e2a9c1000
[*] libc_leak = 0x7fd3c2a51670   libc_base = 0x7fd3c295b000
[+] shell acquired (og=0xef6c4)
uid=1000(ghostparty) gid=1000(ghostparty) groups=1000(ghostparty)
FLAG{D0n7_f0g07_7H3_c0pY_c0Ns7Ruc70R}
```

`FLAG: FLAG{D0n7_f0g07_7H3_c0pY_c0Ns7Ruc70R}`

#### Môi trường chạy local

Binary là PIE stripped build trên glibc 2.23 còn máy thì glibc hiện đại. Để debug local:

- `libs/` là bộ thư viện nhất quán lấy từ container `ubuntu:16.04` (`ld-2.23.so` + libc `2.23-0ubuntu11.3` + `libstdc++.so.6.0.21` + libm + libgcc)
- Binary có một `PT_LOAD` với `p_align = 0x200000` mà `ld-2.23` từ chối ("not properly aligned"). Patch mọi `p_align` của `PT_LOAD` về `0x1000` (giữ nguyên congruence offset/vaddr) → `ghostparty_align`
- Chạy: `./libs/ld-2.23.so --library-path ./libs ./ghostparty_align`

Payload gửi lên remote không đổi, đây chỉ là tiện ích để verify local.
