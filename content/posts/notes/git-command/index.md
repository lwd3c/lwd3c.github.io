+++
title = 'Git Command'
date = 2026-02-16T21:30:41+07:00
draft = false
categories = ["notes"]
+++

**Link tải:** [git_windows_64](https://git-scm.com/downloads/win)

Đầu tiên tạo 1 folder mới để lưu trữ dữ liệu từ github. Sau đó mở `terminal` trong folder đó và dùng các lệnh sau:

### 1. Khởi tạo kho lưu trữ
    > git init

### 2. Kết nối với kho lưu trữ từ xa trên GitHub
    > git remote add origin <URL-kho-luu-tru-GitHub>

### 3. Thêm file vào vùng chờ
    > git add .

**Nếu chưa có branch `main`:** `git checkout -b main`
    
### 4. Commit thay đổi
    > git commit -m "Thông điệp commit"

### 5. Push code lên GitHub

    git push -u origin main

### 6. Pull về local
    > git pull origin main