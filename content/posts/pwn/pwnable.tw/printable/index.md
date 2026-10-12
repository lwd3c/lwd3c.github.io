+++
title = 'Pwnable.tw - Printable'
date = 2026-09-25T07:56:57+07:00
draft = true
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Printable

`nc chall.pwnable.tw 10307`

Gợi ý của đề: *"Everything is printable"*.

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Printable/printable_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
RUNPATH:    b'.'
Stripped:   No
```

libc đi kèm glibc 2.23. Full RELRO nên GOT read-only; No PIE nên `.text`/`.dynamic`/`.bss` cố định.

`main` chỉ chạy một vòng:

```c
memset(buf, 0, 0x80);
printf("Input :");      // ra fd 1
close(1);               // đóng fd 1 SAU khi in prompt
read(0, buf, 0x80);
printf(buf);            // format string một phát, output không còn chỗ đi
exit(0);
```

#### Bug - format string mù

`printf(buf)` không có đối số variadic. Buffer format string cũng chính là vùng đối số của `printf`, nên đối số positional đầu tiên (`%6$...`) là `buf` - **arg offset = 6**, đo chứ không đoán.

`buf` nằm ở `rbp-0x90`, canary ở `rbp-0x8`, mà `read` đúng `0x80` byte nên buffer chỉ với tới `rbp-0x10` - **không có stack overflow**.

`close(1)` giết kênh output **trước** `printf`, nên không nhìn thấy gì hết. Đó mới là ý nghĩa thật của gợi ý: format string chỉ dùng được như một **cây bút mù**, chỉ `%n` có giá trị. Và vì output bị vứt đi, phải tránh các padding `%Nc` lớn có thể làm `printf` chết giữa chừng - thực tế chỉ ghi byte/short (`%hhn`/`%hn`), giữ tổng output dưới `_IO_BUFSIZ`.

### 2. Khai thác

Các hướng chết:

- **GOT overwrite**: Full RELRO giữ page GOT ở `r--p`
- **ret2libc qua return address**: cần leak libc, mà chỉ có một phát và format string không thể vừa leak vừa hành động
- **Leak rồi hành động qua nhiều vòng**: `main` không bao giờ return, nó gọi `exit(0)`, nên saved return address không bao giờ được dùng

Đo được: section `.dynamic` của ELF nằm ở `0x3fe580`, trong page `0x3fe000-0x3ff000` là **`rw-p`** (hệ quả của layout no-PIE cộng `RUNPATH '.'`). Nên `DT_FINI` và `DT_FINI_ARRAY` - các con trỏ destructor mà `_dl_fini` duyệt lúc `exit()` - **ghi được ngay cả dưới Full RELRO**.

Hành vi `_dl_fini` đo được:

- Ghi đè `d_ptr` của `DT_FINI_ARRAY` (`0x3fe5e8`) hoặc của `DT_FINI` (`0x3fe5b8`) đều cho **kiểm soát RIP** lúc exit
- Tại lời gọi fini-array: `rdi = &_rtld_global+2312` (nội dung 0), `rsi = rdx = 0`, `rax = 0x3fe5f0` (địa chỉ entry `DT_FINI_ARRAYSZ` kế bên)
- **Ngân sách vòng lặp = 1 lần chạy thêm.** Trỏ `DT_FINI → main` cho đúng một lần `main()` nữa; lần exit của `main#2` **không** kích hoạt lại destructor vì guard `l_init_called` của glibc. Đã verify: một `main#2` có `DT_FINI` trỏ vào địa chỉ chưa map vẫn exit sạch (rc 0, không SIGSEGV). Tức là tối đa **hai** phát format string, và không phát nào vừa leak vừa hành động được

#### Primitive thắng

Một global ghi được ở địa chỉ cố định `0x601020` giữ `&_IO_2_1_stdout_` - một con trỏ libc. Kế hoạch:

1. Ghi đè `d_ptr` của `DT_FINI_ARRAY` (`0x3fe5e8`) trỏ tới `0x601020`, giữ `DT_FINI_ARRAYSZ = 8`. Giờ `_dl_fini` *gọi bất cứ thứ gì nằm tại `0x601020`*
2. Cùng phát đó, **partial overwrite 3 byte thấp** của `*(0x601020)` để nó thành địa chỉ one_gadget thay vì `&_IO_2_1_stdout_`
3. Zero entry `DT_FINI_ARRAYSZ` kế bên (`.dynamic` tại `0x3fe5f0`, chính là `rax` lúc gọi) để `envp = [rax] = NULL`

Gadget chọn (verify bằng `one_gadget` trên libc đi kèm, offset `0xef6d0`):

```js
execve("/bin/sh", rsi, [rax])     với rsi == 0 và [rax] == 0
```

#### Điều kiện 1/4096

`*(0x601020) = libc_base + 0x3c4620`. Thay 3 byte thấp bằng 3 byte thấp của one_gadget (`0x0ef6d0`) cho ra `libc_base + 0xef6d0` **chỉ khi không có carry tràn qua bit 24**, tức **chỉ khi bit 12..23 của `libc_base` đều bằng 0** - xác suất `1/4096` mỗi kết nối. Mỗi kết nối có ASLR mới nên thay chỗ leak thiếu bằng vòng retry.

Format string gọn (96 byte) làm: một `%hn` ghi `0x1020` vào slot `d_ptr` của `DT_FINI_ARRAY`, ba `%hhn` cho các byte one_gadget, cộng một `%hhn` để zero `DT_FINI_ARRAYSZ`.

#### Hai chi tiết triển khai

`/bin/sh` kế thừa fd 1 đã đóng nên output bình thường của shell mất. Trên kết nối socket thì fd 2 vẫn là socket, nên payload chạy `exec 1>&2` trước để khôi phục output.

`read(0, buf, 0x80)` là một lần read **có cap**. Payload brute 96 byte, nên nếu gói tin bị gộp thì lần read đó có thể nuốt mất 32 byte đầu của lệnh shell đang xếp hàng và làm hỏng âm thầm một lần trúng 1/4096 thật. Pad payload lên đúng `0x80` byte khiến chuyện đó không thể xảy ra. Verify local: bản brute đã pad trúng ở lần thử thứ 2.

#### Các giá trị đo được

| Giá trị | Ý nghĩa | Cách lấy |
|---|---|---|
| `6` | arg offset của format string | probe `%6$p` / `rsp == buf` tại lời gọi `printf` trong gdb |
| `0x3fe5e8` | slot `d_ptr` của `DT_FINI_ARRAY` | `readelf -d` + gdb `x/gx` |
| `0x3fe5f0` | entry `DT_FINI_ARRAYSZ` = `rax` lúc gọi | thanh ghi trong gdb tại `_dl_fini` |
| `0x601020` | global ghi được giữ `&_IO_2_1_stdout_` | gdb `x/gx`, offset `0x3c4620` của libc đi kèm |
| `0xef6d0` | one_gadget | `one_gadget ./libc.so.6` |
| `1/4096` | xác suất trúng | suy từ điều kiện carry `libc_base bits 12..23 == 0` |

### 3. Kết quả

Local (ASLR off để chứng minh tất định, và bản brute đã pad với ASLR on) đều ra shell thật:

```bash
HIT at 2
P_WNED
uid=1000(lwd3c) gid=1000(lwd3c) groups=1000(lwd3c),4(adm),24(cdrom),27(sudo),...
```

Phần remote thì **chưa lấy được flag** và đã dừng lại có chủ ý. Port challenge áp **token bucket theo IP**: burst 16 worker làm port 10307 trả `ECONNREFUSED` khoảng 90 s (port 80/443 của host vẫn `OPEN`, ICMP bình thường → đúng là throttle theo port và theo IP, không phải host chết).

Đo đặc tính bucket bằng connect trần: tốc độ nhanh ~2.8/s cho 24 ok / 16 refused; `gap=1.0s` → 25/25; `gap=0.5s` → 40/40; `gap=0.3s` → 40/40. Brute thật ở nhịp 0.3 s (~1.1/s) vẫn rút cạn bucket và bị chặn sau khoảng 30 lần.

Kết luận: tốc độ bền vững xấp xỉ tốc độ refill (<= 1/s), mà chờ hình học 1/4096 thì cần hơn 4096 kết nối ở <= 1/s, tức khoảng 1.1 giờ kỳ vọng với đuôi dài hơn nhiều, kèm những lần bị ban 90 giây lặp lại. Shell local đứng làm bằng chứng cho chain, và cách chạy lại remote đã ghi rõ: một worker tuần tự, `gap ~ 1.0s`, backoff khi bị refuse, payload đã pad.
