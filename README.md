
# Demo FIDO2 / WebAuthn (Passkeys) - Môn Bảo Mật Thông Tin

> Dự án nghiên cứu và hiện thực cơ chế xác thực không dùng mật khẩu (**Passwordless Authentication**) dựa trên chuẩn **FIDO2 / WebAuthn**, giúp bảo vệ người dùng trước các cuộc tấn công lừa đảo (Phishing), tấn công giả mạo (Man-in-the-Middle) và rò rỉ dữ liệu xác thực.

---
Hướng dẫn file:
- routes/auth.js - a Khoa (Backend FIDO2)
- public/js/webauthn.js - Huy (Frontend FIDO2)
- public/js/ui.js - Đạt (Frontend UI Controller)
- public/css/style.css - Đạt (Frontend Style)


> 📘 **Tài liệu tham khảo chi tiết nội bộ:** Xem [Sổ Tay Trưởng Nhóm (LEADER_GUIDE.md)](LEADER_GUIDE.md) để nắm rõ quy trình Git không conflict, chiến lược học cùng AI và lộ trình 4 Sprint.

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




PHẦN 1: Hiện tại dự án của bạn đã có những gì?
Sau khi kiểm tra toàn bộ mã nguồn trong thư mục:

Về cấu hình dự án (package.json):
Đã cấu hình chạy ES Module ("type": "module").
Đã cài đặt đầy đủ các thư viện chuẩn cho FIDO2/WebAuthn:
@simplewebauthn/server (v14.0.3): Thư viện chuyên dụng tạo và xác minh challenge ở phía Server.
@simplewebauthn/browser (v14.0.0): Thư viện giúp Frontend tương tác với TouchID, Windows Hello, FaceID, YubiKey trên trình duyệt.
express (v5.2.1) & express-session (v1.19.0): Web server và cơ chế lưu phiên (session).
Về mã nguồn (Codebase):


server.js
: Chưa có code (mới có 1 dòng comment).


public/index.html
: Chưa có code (mới có 1 dòng comment).


README.md
: Đã có khung tài liệu giới thiệu rất chuẩn và các lệnh Git cơ bản. (Tuy nhiên bảng thành viên mới để mẫu 3 người, trong khi nhóm có 4 người).
Về Git & GitHub:
Repository đã liên kết với remote https://github.com/nguyenquockiet2462005/fido2.git.
Các bạn đã thử tạo branch và pull request thành công (feature/member-kiet, feature/dat), chứng tỏ các bạn đã biết sơ qua thao tác cơ bản!
Tóm lại: Dự án hiện tại đang ở vạch xuất phát hoàn hảo để các bạn thiết lập lại cấu trúc chuẩn, chia việc cho 4 người mà không bị dẫm chân lên nhau.

PHẦN 2: Nguyên nhân hay bị "conflict Git" và cách giải quyết cho nhóm 4 người
Người mới dùng Git thường rất sợ bị Merge Conflict (xung đột mã nguồn). Xung đột chỉ xảy ra khi 2 người cùng sửa vào cùng 1 file trên cùng một dòng.

Giải pháp vàng: Chia tách kiến trúc file độc lập ngay từ đầu! Chúng ta sẽ chia dự án thành các file riêng biệt:

text
fido2-datphit2lo/
├── server.js              <-- Người 1 (Trưởng nhóm): Khởi động app, cấu hình session, database tạm
├── routes/
│   └── auth.js            <-- Người 2 (Backend FIDO2): Các API tạo challenge và verify chữ ký
└── public/
    ├── index.html         <-- Người 4 (Frontend UI/UX): Cấu trúc giao diện
    ├── css/
    │   └── style.css      <-- Người 4 (Frontend UI/UX): Trang trí giao diện & hiệu ứng
    └── js/
        ├── ui.js          <-- Người 4: Hiển thị thông báo, chuyển tab Đăng ký / Đăng nhập
        └── webauthn.js    <-- Người 3 (Frontend FIDO2): Gọi API và kích hoạt vân tay/TouchID
Khi mỗi thành viên làm việc trên file riêng của mình, việc ghép code (Merge Pull Request) trên GitHub sẽ tự động thành công 100% mà không bao giờ bị conflict.

PHẦN 3: Bảng phân chia công việc cho 4 thành viên
Thành viên	Vai trò	Trách nhiệm chính	File phụ trách
Bạn (Người 1)	Tech Lead & Backend Core	- Dựng khung Express server, cấu hình session, mock in-memory DB.
- Quản lý GitHub, duyệt Pull Request của 3 bạn.
- Ghép nối và kiểm thử toàn hệ sinh thái.	server.js
db.js (hoặc biến lưu tạm user)
Thành viên 2	Backend FIDO2 Specialist	- Viết 4 API cốt lõi với @simplewebauthn/server:
1. Tạo Registration Options (Challenge)
2. Xác minh Registration Response
3. Tạo Authentication Options
4. Xác minh Authentication Response	routes/auth.js
Thành viên 3	Frontend FIDO2 Specialist	- Tích hợp @simplewebauthn/browser.
- Viết hàm gọi API backend lấy Challenge.
- Kích hoạt trình duyệt mở TouchID / Windows Hello.
- Gửi kết quả chữ ký ngược lại cho Server.	public/js/webauthn.js
Thành viên 4	Frontend UI/UX & Live Visualizer	- Thiết kế giao diện hiện đại (Form đăng ký, đăng nhập, Dashboard).
- Đặc biệt: Làm hộp Live Security Inspector (Console) trên web để khi bấm xác thực, màn hình hiển thị từng bước Challenge-Response đang diễn ra (điểm cộng cực lớn khi báo cáo).
- Soạn kịch bản demo và slide thuyết trình.	public/index.html
public/css/style.css
public/js/ui.js
PHẦN 4: Chiến lược "Học & Code cùng AI để THẬT SỰ HIỂU"
Đừng bao giờ prompt: "Viết cho tôi toàn bộ dự án FIDO2". Kết quả sẽ là 500 dòng code lạ lẫm, các bạn copy vào chạy được nhưng lúc thầy cô hỏi 1 câu là "đứng hình".

Hãy hướng dẫn 3 bạn còn lại học theo 3 nguyên tắc sau:

Quy tắc "Hỏi nguyên lý trước - Xin code sau":
Ví dụ hỏi AI: "FIDO2 Registration Challenge là gì? Tại sao Server phải tạo Challenge ngẫu nhiên mà không để Client tự tạo?" (Để chống tấn công Replay Attack).
Quy tắc "Bắt AI chú thích chi tiết từng dòng":
Ví dụ hỏi AI: "Hãy viết giúp tôi hàm generateRegistrationOptions của @simplewebauthn/server và giải thích chi tiết ý nghĩa của các tham số rpName, rpID, userID, challenge bằng tiếng Việt."
Quy tắc "Vấn đáp trước khi Merge Code" (Trách nhiệm của bạn - Nhóm trưởng):
Khi một bạn tạo Pull Request, bạn hãy hỏi bạn đó 2 câu hỏi ngắn về đoạn code bạn ấy vừa đẩy lên:
Ví dụ hỏi Người 2: "Hàm verifyRegistrationResponse cần những tham số gì để xác thực được người dùng?"
Ví dụ hỏi Người 3: "Hàm startRegistration của trình duyệt trả về đối tượng gì?"
Nếu bạn ấy trả lời được, bạn mới bấm Merge. Đây là cách giúp cả 4 người cùng tiến bộ cực kỳ nhanh.
PHẦN 5: Quy trình Git & GitHub chuẩn cho nhóm (Từng bước thao tác)
Hãy copy đoạn này gửi vào nhóm Zalo/Discord của nhóm bạn:

bash
# BƯỚC 1: Luôn cập nhật code mới nhất từ main trước khi làm
git checkout main
git pull origin main
# BƯỚC 2: Tạo nhánh riêng theo đúng tên việc của mình (chỉ tạo 1 lần)
# Người 2:
git checkout -b feature/backend-fido2
# Người 3:
git checkout -b feature/frontend-fido2
# Người 4:
git checkout -b feature/frontend-ui
# BƯỚC 3: Làm việc trên các file của mình, sau đó lưu lại
git status              # Kiểm tra xem mình đã sửa file nào
git add .               # Chuẩn bị lưu
git commit -m "feat: mo ta ngan gon viec da lam"
# BƯỚC 4: Đẩy nhánh lên GitHub
git push origin <ten-nhanh-cua-ban>
# BƯỚC 5: Lên link GitHub (https://github.com/nguyenquockiet2462005/fido2)
# Bấm nút vàng "Compare & pull request" -> Ghi nội dung -> Bấm "Create pull request"
# Báo Nhóm trưởng vào kiểm tra và Merge vào main!
PHẦN 6: Kế hoạch 4 Sprint (Lộ trình hành động ngay)
Sprint 1 (Ngay hôm nay - 1 ngày): Khởi tạo khung dự án & Test Git
Trưởng nhóm (Bạn):
Tạo cấu trúc thư mục rỗng chuẩn: tạo folder routes, public/css, public/js.
Viết file server.js cơ bản (chạy Express trên cổng 3000, phục vụ thư mục public, cấu hình session).
Commit và push lên main.
Cả 3 thành viên:
Chạy git pull origin main, tạo nhánh riêng của mình và kiểm tra xem máy mình chạy được npm start hay chưa.
Sprint 2 (2 - 3 ngày): Hiện thực luồng ĐĂNG KÝ (Registration / Tạo Passkey)
Người 4 (UI): Tạo giao diện ô nhập Username + Nút "Đăng ký bằng Passkey/Vân tay".
Người 2 (Backend): Viết 2 API:
POST /api/auth/register-options: Sinh challenge và các tùy chọn FIDO2.
POST /api/auth/register-verify: Nhận Public Key từ trình duyệt và lưu lại.
Người 3 (Frontend WebAuthn):
Bắt sự kiện bấm nút Đăng ký -> Gửi username lên backend -> Nhận options -> Gọi startRegistration() của @simplewebauthn/browser -> Gửi kết quả về backend xác minh.
Trưởng nhóm: Hỗ trợ kết nối, test thực tế trên máy (quét vân tay TouchID hoặc Windows Hello).
Sprint 3 (2 - 3 ngày): Hiện thực luồng ĐĂNG NHẬP (Authentication / Quét Passkey)
Tương tự Sprint 2 nhưng cho luồng Đăng nhập (dùng generateAuthenticationOptions và startAuthentication).
Người 1: Sau khi đăng nhập thành công, lưu trạng thái đăng nhập vào req.session.loggedIn = true.
Sprint 4 (2 ngày): Hoàn thiện giao diện, Live Inspector & Kịch bản báo cáo
Người 4 hoàn thiện hộp thoại giải thích luồng (Step-by-step visualizer).
Cả nhóm ngồi lại review toàn bộ code, cùng nhau trả lời các câu hỏi lý thuyết:
Private Key nằm ở đâu? (Nằm trong chip bảo mật TPM / Secure Enclave của máy tính hoặc điện thoại người dùng, không bao giờ gửi qua mạng).
Public Key nằm ở đâu? (Nằm ở Server).
Tại sao FIDO2 chống được Phishing? (Vì trình duyệt tự động đính kèm origin/tên miền vào challenge, hacker tạo trang web giả mạo domain khác sẽ bị từ chối ngay).
BƯỚC ĐẦU TIÊN CỦA BẠN BÂY GIỜ
Bạn có muốn tôi giúp bạn:

Dựng sẵn bộ khung chuẩn cho 

server.js
 (Express + Session + Static Files) và cấu trúc thư mục routes/ cùng public/ có chú thích rõ ràng bằng tiếng Việt?
Soạn sẵn một bản hướng dẫn phân công công việc chi tiết dạng Markdown để bạn cập nhật vào 

README.md
 cho 3 bạn còn lại đọc và làm theo ngay?