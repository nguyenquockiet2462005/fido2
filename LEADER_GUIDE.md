# 🧭 SỔ TAY TRƯỞNG NHÓM: DỰ ÁN DEMO FIDO2 / WEBAUTHN
> **Dành riêng cho Trưởng nhóm** để quản lý công việc, hướng dẫn 3 thành viên, kiểm soát Git/GitHub và đảm bảo cả nhóm hiểu rõ bản chất công nghệ khi làm việc cùng AI.

---

## 📌 MỤC LỤC
1. [Bối Cảnh & Mục Tiêu Nhóm](#1-bối-cảnh--mục-tiêu-nhóm)
2. [Hiện Trạng Dự Án (Baseline)](#2-hiện-trạng-dự-án-baseline)
3. [Kiến Trúc Tách File (Chống Xung Đột Git 100%)](#3-kiến-trúc-tách-file-chống-xung-đột-git-100)
4. [Phân Công Công Việc 4 Thành Viên](#4-phân-công-công-việc-4-thành-viên)
5. [Quy Trình Git & GitHub Từng Bước Dành Cho Người Mới](#5-quy-trình-git--github-từng-bước-dành-cho-người-mới)
6. [Chiến Lược "Học Thật - Hiểu Thật" Cùng AI](#6-chiến-lược-học-thật---hiểu-thật-cùng-ai)
7. [Lộ Trình 4 Sprint Triển Khai Chi Tiết](#7-lộ-trình-4-sprint-triển-khai-chi-tiết)
8. [Bộ Câu Hỏi Cốt Lõi Về FIDO2 Khi Thầy Cô Vấn Đáp](#8-bộ-câu-hỏi-cốt-lõi-về-fido2-khi-thầy-cô-vấn-đáp)

---

## 1. Bối Cảnh & Mục Tiêu Nhóm

* **Nhóm:** 4 thành viên (Sinh viên năm 3).
* **Kinh nghiệm:** Trước đây chủ yếu làm bài tập nhỏ trên lớp, quen copy code từ AI nhưng chưa tự xây dựng dự án hoàn chỉnh. Lần đầu dùng GitHub quản lý mã nguồn.
* **Mục tiêu dự án:**
  * Xây dựng ứng dụng Web Demo cơ chế xác thực **FIDO2 / WebAuthn (Passkeys)** không dùng mật khẩu.
  * Tận dụng AI để tăng tốc độ nhưng **phải hiểu rõ từng dòng code**, từng luồng dữ liệu (Challenge, Response, Chữ ký số, Khóa Public/Private).
  * Tự tin báo cáo, demo và trả lời chất vấn của giảng viên.

---

## 2. Hiện Trạng Dự Án (Baseline)

* **Thư viện đã cài đặt (`package.json`):**
  * `@simplewebauthn/server` (v14.0.3): Tạo challenge và xác thực chữ ký số phía backend.
  * `@simplewebauthn/browser` (v14.0.0): Tương tác với TouchID, Windows Hello, FaceID hoặc Security Key trên trình duyệt.
  * `express` (v5.2.1): Framework web server.
  * `express-session` (v1.19.0): Quản lý phiên đăng nhập và lưu tạm `challenge`.
* **Trạng thái mã nguồn:**
  * `server.js`: Mới chỉ là file khung, chưa viết logic Express.
  * `public/index.html`: Mới chỉ là file khung, chưa có giao diện.
  * Kho mã nguồn: Đã kết nối với GitHub `nguyenquockiet2462005/fido2.git`.

---

## 3. Kiến Trúc Tách File (Chống Xung Đột Git 100%)

> [!TIP]
> **Nguyên tắc vàng tránh Git Merge Conflict:** Xung đột chỉ xảy ra khi 2 người cùng sửa một dòng trong cùng 1 file. Bằng cách phân tách các file độc lập ngay từ đầu, tỷ lệ conflict của nhóm sẽ giảm về **0%**.

Cấu trúc thư mục chuẩn cần triển khai:

```text
fido2-datphit2lo/
├── server.js              <-- Người 1 (Trưởng nhóm): Khởi động Express, Session, In-memory DB
├── routes/
│   └── auth.js            <-- Người 2 (Backend FIDO2): Các API tạo challenge và verify
└── public/
    ├── index.html         <-- Người 4 (Frontend UI/UX): Cấu trúc thẻ HTML
    ├── css/
    │   └── style.css      <-- Người 4 (Frontend UI/UX): CSS giao diện & hiệu ứng
    └── js/
        ├── ui.js          <-- Người 4: Điều khiển giao diện, tab, thông báo lỗi/thành công
        └── webauthn.js    <-- Người 3 (Frontend FIDO2): Gọi API và kích hoạt TouchID/Passkey
```

---

## 4. Phân Công Công Việc 4 Thành Viên

| Thành viên | Vai trò | Trách nhiệm chính | File phụ trách |
| :--- | :--- | :--- | :--- |
| **Người 1 (Trưởng nhóm)** | **Tech Lead & Core Backend** | - Khởi tạo cấu trúc dự án, cấu hình Express, Session, Middleware.<br>- Thiết kế cấu trúc lưu trữ người dùng (In-memory user store).<br>- Quản lý GitHub: Review Pull Request, giải quyết conflict (nếu có), merge code vào `main`.<br>- Ghép nối và kiểm thử toàn hệ thống (End-to-End Test). | `server.js`<br>`package.json`<br>Quản lý PR trên GitHub |
| **Người 2** | **Backend FIDO2 Specialist** | - Tìm hiểu và triển khai `@simplewebauthn/server`.<br>- Viết 4 API cốt lõi:<br>  1. `POST /api/auth/register-options`: Sinh challenge đăng ký.<br>  2. `POST /api/auth/register-verify`: Xác minh và lưu Public Key.<br>  3. `POST /api/auth/login-options`: Sinh challenge đăng nhập.<br>  4. `POST /api/auth/login-verify`: Xác minh chữ ký số đăng nhập. | `routes/auth.js` |
| **Người 3** | **Frontend FIDO2 Specialist** | - Tìm hiểu và triển khai `@simplewebauthn/browser`.<br>- Viết logic JavaScript client-side:<br>  * Hàm bắt sự kiện bấm nút Đăng ký / Đăng nhập.<br>  * Hàm `startRegistration({ optionsJSON })` mở TouchID/Passkey tạo khóa.<br>  * Hàm `startAuthentication({ optionsJSON })` mở TouchID/Passkey ký challenge.<br>  * Gửi kết quả ngược lại cho backend qua `fetch()`. | `public/js/webauthn.js` |
| **Người 4** | **Frontend UI/UX & Live Inspector** | - Thiết kế giao diện hiện đại, trực quan (Form đăng ký, Đăng nhập, Dashboard hồ sơ).<br>- **Tính năng đặc biệt (Điểm cộng lớn khi báo cáo):** Hộp thoại **Live Security Inspector (Console)** trên web hiển thị trực quan từng bước Challenge-Response đang diễn ra theo thời gian thực.<br>- Soạn thảo tài liệu báo cáo, kịch bản demo và slide thuyết trình. | `public/index.html`<br>`public/css/style.css`<br>`public/js/ui.js` |

---

## 5. Quy Trình Git & GitHub Từng Bước Dành Cho Người Mới

> [!IMPORTANT]
> **Quy tắc bất di bất dịch:** Tuyệt đối không ai được commit và push trực tiếp lên nhánh `main`. Mọi thay đổi đều phải thông qua **Nhánh riêng (Branch) -> Pull Request (PR) -> Trưởng nhóm duyệt**.

### Hướng dẫn các thành viên thực hiện hàng ngày:

```bash
# BƯỚC 1: Luôn cập nhật code mới nhất từ main về máy trước khi làm việc
git checkout main
git pull origin main

# BƯỚC 2: Tạo nhánh riêng theo đúng tên tính năng (chỉ tạo 1 lần đầu)
# Nhánh của Người 2:
git checkout -b feature/backend-fido2
# Nhánh của Người 3:
git checkout -b feature/frontend-fido2
# Nhánh của Người 4:
git checkout -b feature/frontend-ui

# (Những lần sau chỉ cần chuyển vào nhánh: git checkout feature/...)

# BƯỚC 3: Tiến hành code trên các file được phân công, sau đó kiểm tra & lưu lại
git status                   # Xem các file vừa chỉnh sửa
git add .                    # Đưa vào danh sách chuẩn bị lưu
git commit -m "feat: mo ta ngan gon viec da lam"

# BƯỚC 4: Đẩy nhánh lên GitHub
git push origin <ten-nhanh-cua-ban>

# BƯỚC 5: Mở trình duyệt vào repo GitHub (https://github.com/nguyenquockiet2462005/fido2)
# - Bấm nút vàng "Compare & pull request"
# - Ghi chú ngắn gọn tính năng vừa làm
# - Bấm "Create pull request"
# - Nhắn Trưởng nhóm vào kiểm tra và Merge vào main!
```

---

## 6. Chiến Lược "Học Thật - Hiểu Thật" Cùng AI

Thay vì yêu cầu AI viết toàn bộ cả dự án rồi copy vào, trưởng nhóm yêu cầu các thành viên làm việc với AI theo **3 nguyên tắc**:

### Nguyên tắc 1: Hỏi nguyên lý trước, xin code sau
* **Câu hỏi mẫu cho Người 2 (Backend):**
  > *"Em đang làm tính năng FIDO2 Registration bằng @simplewebauthn/server. Giải thích cho em Challenge là gì? Tại sao Server phải tạo Challenge ngẫu nhiên và lưu vào session mà không để Client tự tạo?"*
* **Câu hỏi mẫu cho Người 3 (Frontend):**
  > *"Giải thích cho em hàm startRegistration của @simplewebauthn/browser nhận vào những gì và gọi API nào của trình duyệt (WebAuthn API)? Kết quả trả về gồm những thông tin gì?"*

### Nguyên tắc 2: Bắt AI chú thích chi tiết từng tham số bằng tiếng Việt
* Khi nhờ AI viết một hàm, luôn yêu cầu:
  > *"Hãy viết hàm này và thêm chú thích giải thích chi tiết ý nghĩa từng tham số (rpID, rpName, userID, challenge, pubKeyCredParams) bằng tiếng Việt."*

### Nguyên tắc 3: Quy tắc "Vấn đáp trước khi Merge" của Trưởng nhóm
Khi một thành viên gửi Pull Request, trưởng nhóm hỏi nhanh 2 câu:
1. *Đoạn code này xử lý nhiệm vụ gì trong quy trình FIDO2?*
2. *Dữ liệu gửi đi và nhận về là gì?*
Nếu bạn đó hiểu và trả lời được, trưởng nhóm mới bấm **Merge**.

---

## 7. Lộ Trình 4 Sprint Triển Khai Chi Tiết

### 🚀 Sprint 1: Dựng Khung Cơ Bản & Kiểm Thử Quy Trình Git (1 ngày)
* **Trưởng nhóm:**
  * Dựng khung `server.js` (Express, Express-Session, thư mục static `public`).
  * Tạo các file khung: `routes/auth.js`, `public/index.html`, `public/css/style.css`, `public/js/ui.js`, `public/js/webauthn.js`.
  * Đẩy lên `main`.
* **3 Thành viên:**
  * Kéo code về (`git pull origin main`), chạy thử `npm start`, tạo branch riêng và commit 1 dòng test thử quy trình.

---

### 🚀 Sprint 2: Hoàn Thiện Luồng ĐĂNG KÝ (Registration / Tạo Passkey) (2 - 3 ngày)
* **Người 4 (UI):** Tạo giao diện ô nhập Username + Nút "Đăng ký bằng Passkey".
* **Người 2 (Backend):**
  * Route `POST /api/auth/register-options`: Dùng `generateRegistrationOptions()` sinh challenge, lưu challenge vào `req.session.currentChallenge`.
  * Route `POST /api/auth/register-verify`: Dùng `verifyRegistrationResponse()` kiểm tra chữ ký, lưu thông tin Credential (ID, Public Key, Counter) vào danh sách User.
* **Người 3 (Frontend):**
  * Bấm nút -> Gửi Username lên backend lấy options -> Gọi `SimpleWebAuthnBrowser.startRegistration({ optionsJSON })` kích hoạt TouchID / Windows Hello -> Gửi dữ liệu thu được về backend xác minh.
* **Trưởng nhóm:** Kiểm thử luồng Đăng ký thực tế trên máy tính (Mac TouchID / Windows Hello).

---

### 🚀 Sprint 3: Hoàn Thiện Luồng ĐĂNG NHẬP (Authentication / Quét Passkey) (2 - 3 ngày)
* **Người 4 (UI):** Thêm nút "Đăng nhập bằng Passkey" và giao diện Dashboard khi đăng nhập thành công.
* **Người 2 (Backend):**
  * Route `POST /api/auth/login-options`: Dùng `generateAuthenticationOptions()`, truyền danh sách `allowCredentials` của user.
  * Route `POST /api/auth/login-verify`: Dùng `verifyAuthenticationResponse()` so khớp chữ ký với Public Key đã lưu trong Database/Session.
* **Người 3 (Frontend):**
  * Gọi `SimpleWebAuthnBrowser.startAuthentication({ optionsJSON })` -> Quét vân tay ký challenge -> Gửi kết quả về server.
* **Trưởng nhóm:** Lưu trạng thái đăng nhập vào `req.session.loggedIn = true`, bảo vệ route trang cá nhân.

---

### 🚀 Sprint 4: Đánh Bóng UI, Live Inspector & Diễn Tập Báo Cáo (2 ngày)
* **Người 4:**
  * Hoàn thiện hộp thoại **Live Security Inspector**: Hiển thị Payload JSON của Challenge, Public Key, Chữ ký số trực tiếp trên màn hình web để thầy cô thấy rõ dữ liệu thật chạy qua mạng.
  * Thiết kế Slide báo cáo và kịch bản demo.
* **Cả 4 người:**
  * Ngồi lại cùng nhau, chạy thử từ đầu đến cuối và tập dượt trả lời các câu hỏi lý thuyết bảo vệ đồ án.

---

## 8. Bộ Câu Hỏi Cốt Lõi Về FIDO2 Khi Thầy Cô Vấn Đáp

Các câu hỏi giảng viên rất thích hỏi khi chấm bài về FIDO2/WebAuthn:

1. **Câu hỏi:** *Khóa bí mật (Private Key) và Khóa công khai (Public Key) được lưu ở đâu?*
   * **Trả lời:** Private Key được lưu an toàn trong phần cứng bảo mật của thiết bị người dùng (Secure Enclave trên Apple, TPM trên Windows, hoặc YubiKey) và **không bao giờ rời khỏi thiết bị**. Public Key được gửi về lưu trữ tại Server để dùng xác minh chữ ký số trong mỗi lần đăng nhập.

2. **Câu hỏi:** *FIDO2 chống tấn công lừa đảo (Phishing) như thế nào?*
   * **Trả lời:** Nhờ vào tham số `rpID` (Relying Party ID / Tên miền). Trình duyệt web tự động gắn tên miền thực tế của trang web đang mở vào gói tin ký số. Nếu người dùng bị lừa vào trang web giả mạo (ví dụ: `faceb00k-scam.com`), trình duyệt sẽ nhận ra tên miền không khớp với tên miền đã đăng ký khóa và từ chối xác thực.

3. **Câu hỏi:** *Tại sao phải có `challenge` và `counter`?*
   * **Trả lời:**
     * `challenge` là một chuỗi ngẫu nhiên do Server tạo ra cho mỗi phiên xác thực, dùng để chống tấn công phát lại (**Replay Attack**) - hacker không thể lấy lại chữ ký cũ để đăng nhập lần sau.
     * `counter` (bộ đếm chữ ký) giúp phát hiện nếu thiết bị xác thực bị sao chép trái phép (Cloned Authenticator).

---
*Tài liệu được khởi tạo ngày 30/09/2026 - Lưu hành nội bộ nhóm FIDO2.*
