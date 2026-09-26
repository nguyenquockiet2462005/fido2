# 🔐 Demo FIDO2 / WebAuthn (Passkeys) - Môn Bảo Mật Thông Tin

> Dự án nghiên cứu và hiện thực cơ chế xác thực không dùng mật khẩu (**Passwordless Authentication**) dựa trên chuẩn **FIDO2 / WebAuthn**, giúp bảo vệ người dùng trước các cuộc tấn công lừa đảo (Phishing), tấn công giả mạo (Man-in-the-Middle) và rò rỉ dữ liệu xác thực.

---

## 👥 Thành Viên Nhóm & Phân Công

| STT | Họ và Tên | MSSV | Vai Trò / Nhiệm Vụ |
| :---: | :--- | :---: | :--- |
| 1 | *(Họ tên bạn)* | ... | Trưởng nhóm / ... |
| 2 | *(Thành viên 2)* | ... | Frontend / UI WebAuthn |
| 3 | *(Thành viên 3)* | ... | Backend / Xử lý FIDO2 Challenge |

---

## 🛠️ Công Nghệ Sử Dụng

* **Backend**: Node.js, Express.js, Express-Session
* **FIDO2 Server**: `@simplewebauthn/server` (Tạo challenge, xác minh PublicKeyCredential)
* **FIDO2 Client**: `@simplewebauthn/browser` (Tương tác với WebAuthn API trên trình duyệt & thiết bị xác thực như TouchID, Windows Hello, YubiKey)
* **Frontend**: HTML5, CSS3, Vanilla JavaScript

---

## 🚀 Hướng Dẫn Cài Đặt & Chạy Dự Án (Dành cho thành viên mới)

### 1. Tải mã nguồn về máy
Mở Terminal (macOS/Linux) hoặc Git Bash (Windows) và chạy:
```bash
git clone https://github.com/nguyenquockiet2462005/fido2.git
cd fido2
```

### 2. Cài đặt các thư viện cần thiết
```bash
npm install
```

### 3. Khởi động Server
```bash
npm start
```
Mở trình duyệt và truy cập: `http://localhost:3000` (hoặc cổng mà server thông báo).

---

## 🌳 Quy Trình Làm Việc Nhóm Với Git & GitHub (Git Flow)

> [!IMPORTANT]
> **Quy tắc vàng:** Không ai code và đẩy (`push`) trực tiếp lên nhánh `main`. Nhánh `main` là nhánh sản phẩm ổn định dùng để chấm điểm/báo cáo. Mỗi người cần tạo **nhánh riêng** khi làm tính năng, sau đó tạo **Pull Request (PR)** trên web GitHub để cả nhóm cùng kiểm tra rồi mới gộp vào `main`.

### Chu trình 5 bước làm việc mỗi ngày:

1. **Luôn kéo code mới nhất từ `main` về máy trước khi bắt đầu:**
   ```bash
   git checkout main
   git pull origin main
   ```

2. **Tạo nhánh riêng cho công việc của mình:**
   ```bash
   # Ví dụ: bạn làm giao diện người dùng
   git checkout -b feature/frontend-ui

   # Hoặc bạn làm API xử lý FIDO2 backend
   git checkout -b feature/backend-auth
   ```

3. **Code và lưu lại lịch sử (Commit):**
   ```bash
   # Kiểm tra các file bạn vừa chỉnh sửa
   git status

   # Thêm toàn bộ file đã sửa vào danh sách lưu
   git add .

   # Lưu commit với thông điệp rõ ràng
   git commit -m "feat: mo ta ngan gon viec ban vua lam"
   ```

4. **Đẩy nhánh của mình lên GitHub:**
   ```bash
   git push origin <ten-nhanh-cua-ban>
   # Ví dụ: git push origin feature/frontend-ui
   ```

5. **Tạo Pull Request (PR) trên web GitHub:**
   * Mở link repo: [https://github.com/nguyenquockiet2462005/fido2](https://github.com/nguyenquockiet2462005/fido2)
   * Bấm vào nút vàng **Compare & pull request** xuất hiện trên trang.
   * Ghi chú những nội dung bạn đã làm, sau đó bấm **Create pull request**.
   * Nhóm trưởng hoặc thành viên khác vào review và bấm **Merge pull request** để gộp vào `main`.

---

## 📖 Bảng Tra Cứu Câu Lệnh Git Nhanh (Cheat-Sheet)

| Lệnh | Ý nghĩa |
| :--- | :--- |
| `git status` | Kiểm tra trạng thái hiện tại (file nào vừa sửa, file nào chưa lưu). |
| `git pull origin main` | Tải toàn bộ cập nhật mới nhất từ `main` trên GitHub về máy. |
| `git checkout -b <tên-nhánh>` | Tạo một nhánh mới và chuyển ngay sang nhánh đó. |
| `git checkout <tên-nhánh>` | Chuyển đổi qua lại giữa các nhánh. |
| `git branch` | Liệt kê danh sách các nhánh hiện có trên máy. |
| `git add .` | Chuẩn bị lưu tất cả các file vừa chỉnh sửa. |
| `git commit -m "mô tả"` | Lưu lại kèm ghi chú nội dung đã thay đổi. |
| `git push origin <tên-nhánh>` | Đẩy nhánh của mình lên GitHub. |
| `git log --oneline` | Xem lịch sử các lần commit rút gọn. |

---

## ⚠️ Lưu Ý An Toàn & Bảo Mật Dành Cho Nhóm

* **Không đẩy `node_modules` lên Git**: Thư mục này rất nặng và đã được đưa vào file `.gitignore`. Mỗi thành viên tải code về chỉ cần chạy lệnh `npm install`.
* **Không đưa thông tin nhạy cảm lên Git**: Tuyệt đối không commit các file chứa mật khẩu, private key, token bí mật hoặc file `.env` lên kho mã nguồn công khai.