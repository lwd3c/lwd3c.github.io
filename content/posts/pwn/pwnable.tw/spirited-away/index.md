+++
title = 'Pwnable.tw - Spirited Away'
date = 2026-09-19T21:00:38+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Spirited Away

`nc chall.pwnable.tw 10204`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Spirited/spirited_away_patched
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
Stripped:   No
```

Không PIE, không canary, NX bật, Partial RELRO - đất của ret2libc 32-bit cổ điển. libc đi kèm glibc 2.23.

Dịch vụ "movie feedback": mỗi vòng đọc name (heap), age, reason, comment rồi in lại, tăng biến global `cnt`, hỏi có muốn để lại comment nữa không, tối đa 200 lần.

Frame của `survey()`:

```js
ebp-0xE8  char  v1[56]      <- sprintf(v1,"%d comment so far...",cnt)
ebp-0xB0  size_t nbytes=60  <- độ dài read() cho name và comment
ebp-0xAC  size_t var_AC=80  <- độ dài read() cho reason
ebp-0xA8  char  s[80]       <- comment
ebp-0x58  int   age         <- scanf("%d")
ebp-0x54  void* buf         <- malloc(0x3C), về sau free(buf)
ebp-0x50  char  v7[80]      <- reason
ebp+0x00  saved ebp
ebp+0x04  saved eip
```

#### Bug 1 - `sprintf` ghi lố sang biến kế

Chuỗi `"%d comment so far. We will review them as soon as we can"` cộng với `cnt` dạng thập phân cho ra 55 ký tự (`1..9`), 56 (`10..99`) hoặc 57 (`100..199`). `v1` chỉ 56 byte, ngay sau nó là `nbytes`:

- `cnt` 2 chữ số: byte NUL kết thúc rơi vào LSB của `nbytes` → `nbytes = 0`
- `cnt` 3 chữ số: ký tự cuối `'n'` (`0x6e`) rơi vào LSB, NUL rơi vào byte kế → `nbytes = 0x6e` (110)

Verify trong gdb (`*(u32*)($ebp-0xB0)`): vòng `cnt=8` cho `0x3c`; vòng setup cho `0x6e`.

#### Bug 2 - đọc lố buffer reason

`read(0, v7, 80)` đổ đầy đúng 80 byte, không thêm NUL, rồi chương trình `printf("Reason: %s", v7)`. Điền đủ 80 byte là leak stack: `[ebp]` (saved ebp = ebp của `main`), `[ebp+4]` (địa chỉ trả về vào `main`), rồi frame của `main`.

Với `nbytes = 110`, lần `read(0, s, 110)` cho **comment** tràn buffer 80 byte thêm 30 byte, chạm tới `age`, **con trỏ `buf`** (tại `S+0x54`) và mấy byte đầu của buffer reason. Chương trình sau đó gọi `free(buf)` với con trỏ do ta đặt - arbitrary free.

### 2. Khai thác

#### House of Spirit trên stack

Comment tràn chỉ tới `S+0x6D` (`S` = buffer comment), không với tới saved EIP ở `S+0xAC`. Nhưng ghi đè được `buf` thì làm `malloc` trả về một địa chỉ stack, và khi đó lần ghi **name** rơi lên stack, bao gồm cả saved EIP.

Chọn fake fastbin chunk nằm trong buffer reason:

- `P = S + 0x60`, với `S = leaked_ebp - 0xC8` (đo được: `survey_ebp = leaked - 0x20`, nên `S = survey_ebp - 0xA8`)
- slot `buf` ở `S+0x54` → `P` (offset 0x54 của comment)
- header giả: `[P-8] = 0` (prev_size), `[P-4] = 0x41` (size 0x40 → fastbin idx 2), ở offset 0x58 / 0x5C của comment
- kiểm tra chunk kế tiếp của `free()` đọc `chunk_at_offset(mem2chunk(P), 0x40) + 4 = P+0x3C = S+0x9C` = `reason[0x44]`, đặt bằng `0x41`; comment chỉ với tới `S+0x6D` nên không đè lên chỗ này

**Vòng A** (setup, `nbytes=110`): comment đặt `buf = P` và header; trả lời `y` → `free(P)` đẩy `P` vào `fastbin[2]`.

**Vòng B** (trigger, `nbytes=110`): `malloc(0x3C)` pop `P` và trả về địa chỉ stack; `read(0, P, 110)` ghi ROP chain. Các lần ghi reason (`P-8..P+0x47`) và comment (`P-0x10..P+0x0D`) sau đó đều nằm dưới saved ebp nên chain sống sót. Comment của vòng trigger vẫn giữ `buf = P` vì `printf("Name: %s", buf)` chạy **sau** lần đọc comment.

Một điểm về framing input: `scanf("%d")` dùng buffer của stdio còn mọi thứ khác dùng `read()` thô, nên mọi trường phải gửi đồng bộ chặt theo prompt.

#### ROP hai stage

Stage 1 chain:

```js
saved_ebp | puts@plt | main | puts@got
```

`puts(puts@got)` leak địa chỉ `puts` đã resolve. Việc return về `main` là cố ý: `main` gọi `fflush(stdout)`, nhờ vậy leak được đẩy ra ngay cả khi stdout của socket remote là block-buffered. Bản đầu tiên làm `puts` → `read` → pivot `leave;ret` và leak không bao giờ tới trên remote đúng vì lý do này.

```py
libc_base = puts_leak - 0x5f140
```

Stage 2: `main` chạy lại `survey`. Leak lại frame mới rồi làm House of Spirit lần nữa:

```js
saved_ebp | system | 0 | "/bin/sh"
```

Vì `main` được vào lại qua chain của ta nên alignment stack 16 byte lệch đi 8, do đó `survey_ebp = leaked2 - 0x18` và `S2 = leaked2 - 0xC0` (phase 1 dùng `-0xC8`). gdb xác nhận tại `0x80488d3` cho phase 2: `saved_eip = system`, `arg = "/bin/sh"`.

Địa chỉ liên quan: `puts@plt=0x80484a0`, `puts@got=0x804a020`, `read@plt=0x8048450`, `leave;ret=0x80488d3`, `pop ebx;ret=0x8048435`, `main=0x80488d5`. libc đi kèm: `puts=0x5f140`, `system=0x3a940`, `"/bin/sh"=0x158e8b`.

```bash
FLAG{Wh4t_1s_y0ur_sp1r1t_1n_pWn}
uid=1000(spirited_away) gid=1000(spirited_away) groups=1000(spirited_away)
SHELL_OK
```

`FLAG: FLAG{Wh4t_1s_y0ur_sp1r1t_1n_pWn}`
