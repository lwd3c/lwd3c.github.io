+++
title = 'Pwnable.tw'
date = 2026-01-29T21:00:00+07:00
draft = false
categories = ["pwn"]
series = ["Pwnable.tw"]
+++

Writeup các bài trên [pwnable.tw](https://pwnable.tw).

Các bài trong bảng dưới đây đã khai thác xong. Offset và phiên bản libc được ghi theo từng bài; một số bài có môi trường remote khác với bản local.

| Bài | Port | Kỹ thuật |
|---|---|---|
| [Start](start) | 10000 | stack BOF, leak stack bằng `write`, shellcode trên stack |
| [orw](orw) | 10001 | seccomp ORW, shellcode `open`/`read`/`write` |
| [calc](calc) | 10100 | OOB index trên pool, ghi ROP chain vào stack, static ROP |
| [dubblesort](dubblesort) | 10101 | uninitialized read leak libc, `scanf` fail giữ canary, ret2libc |
| [hacknote](hacknote) | 10102 | UAF, con trỏ hàm trên heap, fastbin reuse |
| [Silver Bullet](silver-bullet) | 10103 | desync `strncat`/power, ret2libc hai stage |
| [applestore](applestore) | 10104 | node trên stack chưa khởi tạo, unlink ghi saved EBP |
| [3x17](3x17) | 10105 | `.fini_array` loop, stack pivot, ORW ROP |
| [Re-alloc](re-alloc) | 10106 | `realloc(ptr,0)` UAF, tcache poison, GOT → `printf` → `system` |
| [Bash](bash) | 10108 | gọi dynamic loader trực tiếp để chạy Perl trong jail |
| [Starbound](starbound) | 10202 | dispatch index OOB, pivot `add esp,0x1c`, ORW qua PLT |
| [seethefile](seethefile) | 10200 | tràn BSS vào `FILE *fp`, FSOP qua `fclose` |
| [Death Note](death-note) | 10201 | index âm ghi GOT, shellcode in được tự vá `int 0x80` |
| [Secret Garden](secret-garden) | 10203 | UAF + fastbin dup, FSOP `_IO_list_all` trên glibc 2.23 |
| [Spirited Away](spirited-away) | 10204 | `sprintf` ghi lố `nbytes`, House of Spirit trên stack |
| [BabyStack](babystack) | 10205 | `strncmp` độ dài tự chọn làm oracle, stack reuse, one_gadget |
| [CVE-2018-10387](cve-2018-10387) | 10206 | OpenTFTP, strip một `/` thành đường dẫn tuyệt đối |
| [tcache_tear](tcache-tear) | 10207 | tcache double free, FSOP leak `stdout`, `__free_hook` |
| [Bounty Program α](bounty-program-alpha) | 10208 | trạng thái tĩnh của `strtok` trên chunk đã free |
| [Alive Note](alive-note) | 10300 | index âm, hijack `strlen` để tắt validator, shellcode alnum |
| [MnO2](mno2) | 10301 | shellcode ràng buộc theo bảng nguyên tố hoá học |
| [Secret Of My Heart](secret-of-my-heart) | 10302 | off-by-null do NUL nối thêm, chunk chồng nhau |
| [Kidding](kidding) | 10303 | mọi fd bị đóng, reverse shell ROP trong 100 byte |
| [BookWriter](bookwriter) | 10304 | không có `free()`, House of Orange qua `sysmalloc` |
| [WannaHeap](wannaheap) | 10305 | size validate khác size dùng, ghi NULL vào `stdin` buffer |
| [CAOV](caov) | 10306 | thiếu `return` trong copy assignment operator |
| [Heap Paradise](heap-paradise) | 10308 | fastbin dup, partial overwrite, FSOP không cần leak |
| [HITCON FTP](hitcon-ftp) | 10309 | MessagePack arbitrary read, stack overflow, ORW qua UDP |
| [Re-alloc Revenge](re-alloc-revenge) | 10310 | fake chunk `0x461`, unsorted bin, FSOP leak |
| [Stupid Robot](stupid-robot) | 10311 | sai lệch nhãn bytecode, nhảy qua kiểm tra `admin` |
| [Break Out](break-out) | 10400 | UAF còn trong list, largebin attack → FSOP |
| [Ghost Party](ghost-party) | 10401 | C++ thiếu copy constructor, pivot `__realloc_hook` |
| [De-ASLR](de-aslr) | 10402 | pivot vào `.bss`, leak bằng `_IO_file_write` |
| [unexploitable](unexploitable) | 10403 | partial overwrite GOT thành gadget `syscall` |
| [Stupid Boss](stupid-boss) | 10409 | C++ type confusion, arbitrary read/write, ret2libc |
