+++
title = 'Pwnable.tw - Food Store'
date = 2026-10-01T21:12:07+07:00
draft = true
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

## Food Store

`nc chall.pwnable.tw 10406`

> Bài này **chưa giải xong**. Dưới đây là ghi chép triage và các lớp lỗi đã loại trừ.

### 1. Phân tích Binary

```js
pwndbg> checksec
File:       /home/lwd3c/Desktop/Pwn/pwnable.tw/Food Store/food_store
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled
```

libc là glibc 2.24. `sha256` của binary: `e5c3949ed0700565b25320706ca1b3901a6057d366b059f5cf188a46291176fc`.

#### Seccomp

`sub_F00` cài một BPF filter resolve từ `unk_36E0` qua `prctl(38,1,..)` + `prctl(22,2,&prog)`. Dump bằng `seccomp-tools` trên đúng loader đi kèm:

```js
allow: rt_sigreturn, exit_group, exit, open, read, write, writev, close, mmap, munmap
```

Không có `execve` → đích cuối bắt buộc là ORW.

### 2. Các hướng đã loại

**Mảng ingredient** - disassemble vòng lặp trong `sub_1276`: bound là `cmp 0x9; jle`, đúng 10 slot, không off-by-one. Đường tràn giá trong Cook bị chặn về mặt cấu trúc ở khoảng `13 * 500 * 1.217 ~ 7906`, không đâu gần mức tràn `int32` dù để bao lâu.

**Chefs info** - disassemble các call site `printf_chk` trong `sub_1D5A`: toàn bộ là format string tĩnh (`Name:%s`, `Level:%u`, `Power:%lu`, `Money:%lu`) với đối số global hợp lệ, không có format string bug, không tràn.

**Leak unsorted bin qua recipe** - đo bằng `/proc/pid/mem` thì chunk recipe `0x90` sau khi free có `fd`/`bk` là địa chỉ libc tương đối `main_arena`. Nhưng đường dùng lại duy nhất (Recipe-Add) zero và ghi đè byte 0-127 **trước** mọi lần in, nên không menu path nào để lộ `fd`/`bk` cũ cho người chơi. Dead end.

Phân loại hiện tại trong ledger: `bug = unresolved-pending-dynamic-forks` - RE tĩnh đã loại các lớp overflow / format string / index OOB thông thường; đang săn UAF/double-free trên chunk dish và recipe bằng đo động.
