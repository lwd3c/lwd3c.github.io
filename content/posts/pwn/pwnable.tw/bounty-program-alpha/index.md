+++
title = 'Pwnable.tw - Bounty Program α'
date = 2026-09-22T20:28:58+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Bounty Program α

`nc chall.pwnable.tw 10208`

Bài gốc từ HITCON CTF Final 2019.

### 1. Phân tích Binary

Binary `bounty_program` là ELF PIE stripped, chạy qua một launcher `wrapper`. libc đi kèm là glibc 2.27.

```js
pwndbg> checksec
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled
```

`wrapper` đọc `Name:`/`Value:` rồi `setenv` một biến môi trường tuỳ ý (chặn chuỗi con `LD` và `MALLOC`), cài seccomp-bpf, rồi `execveat(322, 100, "/home/bounty_program/bounty_program", ...)`, kèm `alarm(300)`.

Seccomp allowlist giải từ BPF trong `.rodata`:

```js
read, write, open, openat, close, mmap, mprotect, munmap, brk, access,
fstat, arch_prctl, set_tid_address, set_robust_list, rt_sigprocmask,
rt_sigaction, rt_sigreturn, prlimit64, exit, exit_group, execveat
```

`execve` (59) **không** có trong danh sách; `execveat` (322) và `rt_sigreturn` (15) thì có.

#### Bug - trạng thái tĩnh của `strtok`

Trong handler "Add type":

```c
printf("Size:"); size = read_long();          // atoll, signed, không kiểm tra
s = calloc(1, size);                           // âm hoặc quá lớn -> NULL
printf("Type:"); read_str(s, size);            // s == NULL -> không làm gì
for (t = strtok(s, ","); t; t = strtok(NULL, ",")) {   // s == NULL -> dùng STATIC state
    printf("type: %s\n", t);
    printf("Price:"); read_long();
    add_type_internal(t, price);
}
free(s);
```

Con trỏ tĩnh của `strtok` không được xoá khi duyệt hết chuỗi - nó nằm lại ở byte `'\0'` kết thúc của buffer **trước đó**, mà buffer đó đã `free()` rồi. Một lần `Add type` sau với `calloc` thất bại sẽ tokenize thẳng trên **bộ nhớ heap đã giải phóng**:

- **Info leak**: `printf("type: %s\n", t)` in ra byte trong chunk đã free, tức là `fd` của tcache hoặc `fd`/`bk` của unsorted bin.
- **Ghi byte**: `strtok` thay mỗi delimiter tìm được bằng `0x00`. Một byte `0x2c` (`,`) nằm trong trường `fd`/size của chunk đã free sẽ bị zero hoá → hỏng một phần con trỏ heap / free list.

Còn một điểm yếu phụ ở helper `read_str` (chỉ thêm NUL khi byte cuối đọc được là `\n`), nhưng đường `strtok` mới là đường mạnh.

### 2. Khai thác

glibc 2.27 vẫn còn `__free_hook`/`__malloc_hook`, nhưng seccomp chặn `execve`. Nên đích đến là: ghi `__malloc_hook` thành `leave; ret`, pivot vào ROP chain, chạy `mprotect(heap, 0x1000, 7)` → `read(0, heap, 0x1000)` → `jmp heap`, rồi chạy **shellcode ORW** vì `open`/`read`/`write` đều được phép.

#### Chiến lược leak

Lời giải phổ biến leak heap base bằng brute force từng byte qua `strncmp` của login, khoảng 600 lần đoán. Với server thật thì mỗi lần đoán tốn ~1.3 s RTT và `alarm(300)` của wrapper giết kết nối trước khi xong - không dùng được.

Thay bằng:

1. **Replay đúng chuỗi alloc/free** mà bước corruption về sau phụ thuộc vào, một cách tất định: `register; login('k'*14); unregister` x 5. Cùng chunk được cấp và giải phóng, cùng buffer contact bị leak, nhưng dùng credential **biết trước độ dài** thay vì đoán từng byte.
2. **Chỉ đoán nibble 64 KiB của heap base** `heap & 0xf000` - 16 khả năng - cho hai kích thước description khổng lồ của `Submit a bug report`. Đoán sai thì corruption không cho ra con trỏ libc, loại run đó và thử lại trên kết nối mới.
3. **Leak libc**: sau corruption + 7 lần `Add type(0x148)` + `Delete report`, Title của một report chồng lên chunk unsorted bin, nên `Show vulnerability` in ra `main_arena+0x60`. `libc_base = leak - 0x3ebca0`.
4. **Leak heap**: `Add type(0xf8)`, `Remove type(0x18, 'DoS')`, Title của report khi đó leak heap base (`u64(title) - 0x510`), verify page-aligned và `& 0xf000` khớp với nibble đã đoán.
5. Ghi fake tcache entry và `__malloc_hook = leave; ret` qua Title của `Modify report`, trigger `calloc`, chạy ROP + shellcode ORW.

#### Các giá trị đo được

| Giá trị | Cách lấy |
|---|---|
| `main_arena+0x60` → `libc_base` | Title leak của `Show vulnerability` sau khi chồng unsorted bin |
| offset unsorted bin `0x3ebca0` | `__malloc_hook` = `0x3ebc30` trong libc đi kèm, bám theo run thật |
| heap base | Title leak sau `Remove type('DoS')`, trừ `0x510` |
| `pop rdi/rsi/rdx/rax`, `syscall`, `leave` | gadget libc `0x2155f / 0x23e6a / 0x1b96 / 0x439c8 / 0xd2975 / 0x54803` |
| `heap & 0xf000` | đoán 16 khả năng, verify lại bằng heap leak sau đó |

Local chạy `run/bounty_program_patched` (với `libc.so` + `ld-2.27.so` của bài) in ra marker trước khi bắn remote. Remote mỗi lần thử dưới 60 s, chạy 6 worker song song, hai worker trúng ngay lần đầu với nibble `0x0`.

```bash
$ python3 solve2.py REMOTE
[+] libc 0x7f2e852bf000
[+] heap 0x563905200000 (guess nibble 0x0)
FLAG{s0m3_3nv_Ar3_pw3rful_it_h3lp_you_lif3_mor3_e4sy}
```

`FLAG: FLAG{s0m3_3nv_Ar3_pw3rful_it_h3lp_you_lif3_mor3_e4sy}`
