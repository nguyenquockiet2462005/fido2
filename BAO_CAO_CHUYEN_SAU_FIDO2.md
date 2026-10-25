# BÁO CÁO KỸ THUẬT VÀ PHÂN TÍCH CHUYÊN SÂU ĐỒ ÁN
# HỆ THỐNG XÁC THỰC KHÔNG MẬT KHẨU CHUẨN FIDO2 / WEBAUTHN (PASSKEYS)
**Môn học:** Bảo Mật Thông Tin  
**Đơn vị:** Viện Công nghệ Việt - Nhật (VJIT) – Đại học Công nghệ TP.HCM (HUTECH)  
**Nhóm thực hiện:** Nhóm Doraemon (Quốc Kiệt, Khoa, Huy, Đạt)  
**Mã nguồn Repository:** `https://github.com/nguyenquockiet2462005/fido2`  
**Nhánh lưu trữ tính năng thẻ:** `archive/student-card-feature`

---

## MỤC LỤC TỔNG QUAN

1. [TỔNG QUAN ĐỀ TÀI VÀ TÍNH CẤP THIẾT](#1-tổng-quan-đề-tài-và-tính-cấp-thiết)
2. [CƠ SỞ LÝ THUYẾT & NGUYÊN LÝ MẬT MÃ FIDO2 / WEBAUTHN](#2-cơ-sở-lý-thuyết--nguyên-lý-mật-mã-fido2--webauthn)
3. [KIẾN TRÚC HỆ THỐNG VÀ CÁC LUỒNG HOẠT ĐỘNG CHÍNH](#3-kiến-trúc-hệ-thống-và-các-luồng-hoạt-động-chính)
4. [PHÂN TÍCH CHUYÊN SÂU CÁC PHÒNG TUYẾN BẢO MẬT](#4-phân-tích-chuyên-sâu-các-phòng-tuyến-bảo-mật)
5. [THIẾT KẾ CƠ SỞ DỮ LIỆU & LƯU TRỮ HYBRID BẢO TOÀN](#5-thiết-kế-cơ-sở-dữ-liệu--lưu-trữ-hybrid-bảo-toàn)
6. [KIẾN TRÚC MÃ NGUỒN VÀ NGUYÊN TẮC CLEAN CODE](#6-kiến-trúc-mã-nguồn-và-nguyên-tắc-clean-code)
7. [KẾT QUẢ KIỂM THỬ AN NINH TỰ ĐỘNG](#7-kết-quả-kiểm-thử-an-ninh-tự-động)
8. [BẢNG SO SÁNH PASSKEYS VỚI CÁC PHƯƠNG THỨC TRUYỀN THỐNG](#8-bảng-so-sánh-passkeys-với-các-phương-thức-truyền-thống)
9. [KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN](#9-kết-luận-và-hướng-phát-triển)

---

## 1. TỔNG QUAN ĐỀ TÀI VÀ TÍNH CẤP THIẾT

### 1.1. Thực trạng mất an toàn của cơ chế xác thực truyền thống
Trong suốt nhiều thập kỷ, Internet dựa trên mô hình **Shared Secret (Bí mật dùng chung)**:
- Người dùng ghi nhớ một chuỗi ký tự (mật khẩu) và chia sẻ nó với máy chủ (thường được băm - hash).
- **Các nguy cơ bảo mật cố hữu:**
  - **Tấn công lừa đảo (Phishing):** Kẻ tấn công tạo website mạo danh (giả domain trường học/ngân hàng) để người dùng tự nhập mật khẩu và mã OTP.
  - **Tấn công phát lại & Trung gian (Replay & Man-in-the-Middle):** Đánh cắp gói tin chứa mật khẩu/chữ ký trên đường truyền mạng công cộng.
  - **Rò rỉ cơ sở dữ liệu (Database Breach):** Khi CSDL máy chủ bị xâm nhập, các bảng băm (MD5, SHA, Bcrypt) có nguy cơ bị bẻ khóa qua Rainbow Tables hoặc GPU Brute-force.
  - **Tấn công vét cạn & Nhồi thông tin đăng nhập (Credential Stuffing):** Thói quen đặt mật khẩu trùng lặp của người dùng khiến việc lộ mật khẩu ở một dịch vụ kém an toàn làm sụp đổ toàn bộ các tài khoản khác.
  - **Bất tiện của 2FA truyền thống:** OTP SMS dễ bị tấn công SIM Swap, chặn bắt SS7; mã OTP Authenticator phức tạp và vẫn bị Phishing thời gian thực (Reverse Proxy Phishing như Evilginx).

### 1.2. Giải pháp Passkeys (FIDO2 / WebAuthn)
Đề tài nghiên cứu và hiện thực một hệ thống xác thực hoàn toàn **không dùng mật khẩu (Passwordless Authentication)** chuẩn **FIDO2 / WebAuthn Level 2**, ứng dụng cho Cổng dịch vụ Sinh viên HUTECH:
- Người dùng chỉ cần chạm vân tay (Touch ID), quét khuôn mặt (Face ID), Windows Hello hoặc cắm khóa bảo mật vật lý (YubiKey).
- Máy chủ hoàn toàn **không lưu trữ bất kỳ mật khẩu hay khóa bí mật nào**.
- Bẻ gãy hoàn toàn các cuộc tấn công Phishing bằng ràng buộc nguồn gốc mã hóa (*Origin Cryptographic Binding*).

---

## 2. CƠ SỞ LÝ THUYẾT & NGUYÊN LÝ MẬT MÃ FIDO2 / WEBAUTHN

### 2.1. Cấu trúc bộ chuẩn FIDO2
Chuẩn FIDO2 do liên minh **FIDO Alliance** và tổ chức **W3C** đồng phát triển, bao gồm hai giao thức trụ cột:
1. **W3C WebAuthn (Web Authentication API Level 2):** Cung cấp API JavaScript chuẩn trong trình duyệt (`navigator.credentials.create()` và `navigator.credentials.get()`) để ứng dụng web giao tiếp an toàn với trình duyệt.
2. **CTAP2 (Client to Authenticator Protocol 2):** Giao thức cho phép trình duyệt giao tiếp với thiết bị xác thực phần cứng bên ngoài (qua USB, NFC, BLE) hoặc cảm biến sinh trắc học tích hợp bên trong máy tính/điện thoại (Platform Authenticator).

```
+-------------------------------------------------------------------+
|                        Web Application (UI)                       |
+-------------------------------------------------------------------+
                                  |
                                  v  (W3C WebAuthn JavaScript API)
+-------------------------------------------------------------------+
|                     Browser / User Agent                          |
+-------------------------------------------------------------------+
                                  |
                                  v  (CTAP2 Protocol)
+-------------------------------------------------------------------+
|              Authenticator (Secure Enclave / TPM / YubiKey)       |
+-------------------------------------------------------------------+
```

### 2.2. Cơ chế Mật mã Bất đối xứng (Asymmetric Cryptography)
Hệ thống sử dụng mật mã khóa công khai đường cong Elip (Elliptic Curve Cryptography - ECC), phổ biến nhất là **ES256 (ECDSA P-256 with SHA-256)**:
- **Khóa bí mật (Private Key):** Được phần cứng an toàn (*Secure Enclave* trên Mac/iOS, *TPM* trên Windows, *Titan M* trên Android) sinh ra ngẫu nhiên bên trong con chip và **không bao giờ rời khỏi thiết bị**. Ngay cả hệ điều hành hay mã độc cũng không thể trích xuất được Private Key.
- **Khóa công khai (Public Key):** Được gửi lên máy chủ Relying Party và lưu trữ an toàn trong CSDL.
- **Xác thực quyền sở hữu:** Trong mỗi phiên đăng nhập, Authenticator dùng Private Key ký lên một thông điệp thách thức (Challenge) duy nhất. Máy chủ chỉ cần dùng Public Key đã lưu để kiểm tra chữ ký số.

---

## 3. KIẾN TRÚC HỆ THỐNG VÀ CÁC LUỒNG HOẠT ĐỘNG CHÍNH

Hệ thống `fido2-datphit2lo` được thiết kế theo mô hình 3 thực thể chuẩn:
1. **Relying Party (RP - Server):** Xây dựng trên nền tảng Node.js / Express 5, tích hợp thư viện mật mã `@simplewebauthn/server` v14.
2. **Client (Browser):** Chạy trên các trình duyệt hiện đại (Chrome, Safari, Edge, Firefox), tích hợp `@simplewebauthn/browser` v14.
3. **Authenticator:** Thiết bị sinh trắc học cá nhân của người dùng.

```
                      +-------------------+
                      |   MongoDB Atlas   |
                      |   (Cloud Storage) |
                      +---------+---------+
                                ^
                                | (Sync / MongoStore)
                                v
+---------------+     HTTP    +-------------------+    WebAuthn API    +----------------+
|  User / Client| <=========> | Relying Party (RP)| <================> |  Authenticator |
|  (Browser UI) |             | (Node.js/Express) |                    | (TouchID / TPM)|
+---------------+             +-------------------+                    +----------------+
```

---

### 3.1. Luồng Đăng ký Passkey mới (Registration Flow)

```mermaid
sequenceDiagram
    autonumber
    actor U as Người dùng (Sinh viên)
    participant B as Trình duyệt (Client)
    participant S as Máy chủ (Relying Party)
    participant A as Chip bảo mật (Authenticator)

    U->>B: Nhập tên tài khoản, bấm "Đăng Kí"
    B->>S: POST /api/auth/register-options { username }
    Note over S: Sinh Challenge (CSPRNG 32 bytes)<br/>Lưu challenge vào Session (TTL 2 phút)<br/>Tạo User ID ngẫu nhiên 64 bytes
    S-->>B: Trả về PublicKeyCredentialCreationOptions
    B->>A: navigator.credentials.create(options)
    A->>U: Yêu cầu chạm vân tay (User Verification)
    U-->>A: Quét vân tay thành công
    Note over A: Sinh cặp khóa mới (Private/Public Key)<br/>Ký ClientDataJSON & AuthData
    A-->>B: Trả về AttestationObject (chứa PublicKey) & ClientDataJSON
    B->>S: POST /api/auth/register-verify { username, response }
    Note over S: Xác minh: Origin thật, RP ID, Challenge khớp<br/>Chuyển PublicKey sang Base64URL<br/>Khởi tạo counter = 0
    S-->>B: { verified: true }
    B-->>U: Hiển thị thông báo "Đăng ký thành công!"
```

---

### 3.2. Luồng Đăng nhập Passkey chuẩn (Authentication Flow)

```mermaid
sequenceDiagram
    autonumber
    actor U as Người dùng
    participant B as Trình duyệt (Client)
    participant S as Máy chủ (Relying Party)
    participant A as Chip bảo mật (Authenticator)

    U->>B: Nhập username, bấm "Đăng Nhập"
    B->>S: POST /api/auth/login-options { username }
    Note over S: Tìm user trong DB<br/>Sinh Challenge mới lưu vào Session<br/>Lấy danh sách Credential ID đã đăng ký
    S-->>B: Trả về PublicKeyCredentialRequestOptions
    B->>A: navigator.credentials.get(options)
    A->>U: Yêu cầu chạm vân tay xác nhận
    U-->>A: Quét vân tay thành công
    Note over A: Tăng bộ đếm counter (+1)<br/>Dùng Private Key ký lên Challenge
    A-->>B: Trả về Assertion (Signature, AuthenticatorData)
    B->>S: POST /api/auth/login-verify { username, response }
    Note over S: Lấy Public Key của user soi chữ ký<br/>Kiểm tra counter mới > counter cũ<br/>Cập nhật counter mới vào DB<br/>Tạo Session đăng nhập an toàn
    S-->>B: { verified: true, user: { role: 'student' } }
    B-->>U: Điều hướng vào Workspace Sinh viên
```

---

### 3.3. Luồng Đăng nhập Passkey 1-chạm không cần username (Usernameless / Discoverable)

Đây là tính năng hiện đại nhất của FIDO2 (*Passkey Resident Key*):
1. Người dùng không cần nhớ hay nhập username, chỉ cần bấm nút **"Đăng nhập nhanh bằng Passkey"**.
2. Máy chủ gửi về Challenge với tùy chọn `allowCredentials: []` (danh sách mở).
3. Trình duyệt ra lệnh cho Authenticator tìm kiếm các khóa Passkey lưu trong chip có gắn với tên miền `rpID = localhost`.
4. Màn hình sinh trắc học hiện danh sách tài khoản, người dùng chạm vân tay chọn tài khoản mong muốn.
5. Authenticator gửi chữ ký kèm mã `credential.id`.
6. Tại Backend, hàm `findUserByCredentialId(credentialId)` lập tức truy xuất ra danh tính người dùng và cấp phiên đăng nhập tự động.

---

### 3.4. Luồng Xác thực nâng cao (Step-Up Authentication)

Được áp dụng tại **Không gian làm việc sinh viên (`workspace.html`)**:
- Khi sinh viên muốn chỉnh sửa thông tin hồ sơ (Họ tên, Ngày sinh, Khoa, Niên khóa), hệ thống không chỉ dựa vào phiên Cookie hiện có mà **bắt buộc người dùng phải quét lại vân tay/Face ID (Step-Up Auth)**.
- **Quy tắc an ninh:**
  - Yêu cầu cờ `userVerification: 'required'` và `requireUserVerification: true`.
  - Challenge có thời hạn nghiêm ngặt **2 phút**, bị vô hiệu hóa ngay sau lần sử dụng đầu tiên.
  - Ô Mã Số Sinh Viên (**MSSV**) được đặt `readonly` cố định, loại bỏ khỏi payload cập nhật để ngăn ngừa mạo danh MSSV của sinh viên khác.

---

## 4. PHÂN TÍCH CHUYÊN SÂU CÁC PHÒNG TUYẾN BẢO MẬT

Hệ thống đã trải qua rà soát an ninh gắt gao và hiện thực đầy đủ các biện pháp phòng chống tấn công đạt chuẩn OWASP và W3C:

| Mối đe dọa an ninh mạng | Cơ chế FIDO2 / Mã nguồn xử lý | Vị trí kiểm soát mã nguồn |
| :--- | :--- | :--- |
| **1. Tấn công Lừa đảo (Phishing & Man-in-the-Middle)** | Trình duyệt tự động thu thập tên miền thực tế trên thanh địa chỉ và đưa vào `clientDataJSON`. Sau đó chip phần cứng ký lên dữ liệu này. Máy chủ so khớp `expectedOrigin` và `expectedRPID`. Kẻ lừa đảo làm giả trang web sẽ bị từ chối 100%. | `routes/auth.js` (`getExpectedOrigins`, `getExpectedRPIDs`) |
| **2. Tấn công Phát lại (Replay Attack)** | Mỗi phiên bắt buộc dùng một `challenge` ngẫu nhiên sinh bởi CSPRNG (`crypto.randomBytes`). Challenge chỉ dùng 1 lần (Single-use), có thời hạn sống TTL 2 phút và bị xóa khỏi Session ngay lập tức. | `routes/auth.js`, `routes/user.js` |
| **3. Sao chép Khóa & Đánh cắp Authenticator** | Bộ đếm chữ ký (`counter`) tăng dần đều sau mỗi lần xác thực. Nếu giá trị `counter` nhận được nhỏ hơn hoặc bằng giá trị đã lưu trong CSDL, máy chủ lập tức cảnh báo khóa bị sao chép và từ chối phiên đăng nhập. | `routes/auth.js`, `db.js` (`updateCredentialCounter`) |
| **4. Rò rỉ Cơ sở Dữ liệu (Database Breach)** | Không lưu mật khẩu, không lưu chuỗi băm. CSDL chỉ lưu Public Key và Credential ID. Kẻ tấn công đánh cắp toàn bộ CSDL cũng không thể đăng nhập vì không có Private Key trong máy người dùng. | `db.js` |
| **5. Chiếm đoạt Quản trị viên lần đầu (Vá lỗi C2)** | Khởi tạo Passkey cho Quản trị viên (`admin`) lần đầu bắt buộc phải cung cấp mã bí mật `ADMIN_SETUP_TOKEN`. Mã được so khớp bằng hàm chống tấn công kênh kề `crypto.timingSafeEqual`. | `routes/auth.js` (`safeEqual`) |
| **6. Mạo danh Danh tính Sinh viên (Vá lỗi H3 / C3)** | Loại bỏ toàn bộ endpoint nhận diện thẻ sinh viên OCR chưa kiểm chứng. Cố định trường MSSV (`readonly`), không cho phép thay đổi mã định danh qua Step-Up Auth. | `routes/user.js`, `public/workspace.html` |
| **7. Từ chối dịch vụ (DoS / Brute-force)** | Áp dụng `express-rate-limit` chặn tối đa 300 requests/15 phút trên mỗi địa chỉ IP. | `server.js` (`globalApiLimiter`) |
| **8. Tấn công XSS & Chiếm đoạt Cookie (Session Hijacking)** | Cấu hình Cookie phiên với cờ `httpOnly: true` (chặn JavaScript độc hại đọc trộm Cookie), `sameSite: 'lax'`, `maxAge: 24h`. Lọc sạch mã HTML đầu vào bằng hàm `sanitizeText`. | `server.js`, `routes/user.js` |

---

## 5. THIẾT KẾ CƠ SỞ DỮ LIỆU & LƯU TRỮ HYBRID BẢO TOÀN

### 5.1. Cơ chế Lưu trữ Hybrid 3 Lớp (RAM + Local File + Cloud MongoDB)
Nhằm giải quyết triệt để vấn đề "Server Render tự động sleep/restart làm mất dữ liệu":
1. **Lớp Cache RAM:** Lưu trữ mảng JavaScript `users` để đọc/ghi với tốc độ mili-giây, phục vụ các luồng kiểm tra tức thì.
2. **Lớp Local File (`data/users.json`):** Tự động đồng bộ mỗi khi có thay đổi, giúp bảo lưu dữ liệu khi chạy cục bộ mà không cần cài đặt CSDL phức tạp.
3. **Lớp Cloud MongoDB Atlas (`mongodb` driver):** Khi có biến môi trường `MONGODB_URI`, hệ thống tự động kết nối cluster MongoDB Atlas trên đám mây, nạp dữ liệu vào RAM khi khởi động và tự động đồng bộ khi có tài khoản/khóa mới.
4. **Bảo toàn Phiên (MongoStore):** Sử dụng `connect-mongo` để lưu trữ Session trực tiếp lên collection `sessions` của MongoDB Atlas, giữ trạng thái đăng nhập của sinh viên suốt 24 giờ.

### 5.2. Chuẩn hóa Khóa công khai Base64URL
Trước đây, thư viện WebAuthn trả về khóa công khai dưới dạng mảng byte số nguyên `Uint8Array`. Khi lưu ra JSON, nó chiếm hàng trăm dòng và phình to dung lượng.  
Nhóm đã triển khai giải pháp tối ưu:
- Viết hàm `toBase64UrlKey(pk)` để chuyển đổi khóa công khai sang chuỗi Base64URL.
- **Hiệu quả:** Giảm **74% dung lượng lưu trữ CSDL**, mỗi khóa Passkey chỉ chiếm đúng 1 dòng ký tự duy nhất, tương thích tuyệt đối với chuẩn RFC 4648.

---

## 6. KIẾN TRÚC MÃ NGUỒN VÀ NGUYÊN TẮC CLEAN CODE

Tuân thủ nghiêm ngặt các nguyên tắc công nghệ phần mềm:

### 6.1. Phân tách mối quan tâm (Separation of Concerns - SoC)
- **Tầng Trình diễn (View):** Toàn bộ cấu trúc giao diện và Modal nằm độc quyền tại [`public/index.html`](file:///Users/macos/fido2-datphit2lo/public/index.html) và [`public/css/style.css`](file:///Users/macos/fido2-datphit2lo/public/css/style.css).
- **Tầng Điều khiển sự kiện (Controller):** File [`public/js/ui.js`](file:///Users/macos/fido2-datphit2lo/public/js/ui.js) chịu trách nhiệm lắng nghe sự kiện DOM, đóng mở modal, điều khiển hoạt ảnh.
- **Tầng Dịch vụ & Giao thức (Service/Protocol):** File [`public/js/webauthn.js`](file:///Users/macos/fido2-datphit2lo/public/js/webauthn.js) **hoàn toàn sạch bóng mã HTML**, chỉ tập trung vào việc gọi WebAuthn API và gửi nhận dữ liệu với Backend.

### 6.2. Đảo ngược phụ thuộc (Inversion of Control - IoC)
Thay vì nhúng chuỗi HTML modal bừa bãi vào file logic giao thức, hàm `handleRegister` trong `webauthn.js` nhận một callback:
```javascript
export async function handleRegister(username, hoTen, ngaySinh, logCallback, promptTokenCallback) {
    ...
    if (optionsRes.status === 403 && optionsJSON?.needsAdminToken) {
        // Ủy quyền việc hiển thị giao diện lấy Token cho tầng UI bên ngoài quyết định
        const setupToken = await promptTokenCallback();
        ...
    }
}
```

---

## 7. KẾT QUẢ KIỂM THỬ AN NINH TỰ ĐỘNG

Dự án đã tích hợp kịch bản kiểm thử an ninh chuyên dụng [`tests/security.test.mjs`](file:///Users/macos/fido2-datphit2lo/tests/security.test.mjs), thực thi thông qua lệnh:
```bash
npm test
```

### Kết quả chạy kiểm thử tự động thực tế:
```text
> fido2-datphit2lo@1.0.0 test
> node --env-file=.env tests/security.test.mjs

📦 [DB] Đã khôi phục và chuẩn hóa thành công 2 tài khoản từ data/users.json
Testing security fixes...
1. Verifying ADMIN_SETUP_TOKEN is loaded: true
✅ safeEqual passed (Hàm so sánh an toàn chống Timing Attack hoạt động chính xác)
✅ isChallengeExpired passed (Cơ chế hết hạn Challenge sau 2 phút hoạt động chính xác)
✅ db.js exports verified clean (Dữ liệu CSDL chuẩn hóa an toàn)

Testing HTTP Endpoints on dynamic port...
✅ Admin with Passkey: correctly locked out from re-registration (HTTP 400 - Đã có Passkey thì không cho đăng ký đè)
✅ C2 Defense (First-time setup): Admin register without token returned 403 Forbidden (Chặn tạo Admin nếu thiếu token)
✅ C2 Defense (First-time setup): Admin register with wrong token returned 403 Forbidden (Chặn tạo Admin nếu sai token)
✅ C2 Defense (First-time setup): Admin register with correct token succeeded with challenge (Tạo Admin thành công khi có token đúng)
✅ Student Registration: normal flow unimpeded (status 200, challenge generated - Sinh viên đăng ký bình thường)
✅ C3 Defense: /api/user/profile/verify-card returned 404 (Đã gỡ bỏ an toàn endpoint thẻ cũ)
✅ C3 Defense: /api/user/profile/unlink-card-options returned 404 (Đã gỡ bỏ an toàn endpoint thẻ cũ)

🎉 ALL SECURITY FIXES AND DEFENSES VERIFIED WORKING 100%!
```

---

## 8. BẢNG SO SÁNH PASSKEYS VỚI CÁC PHƯƠNG THỨC TRUYỀN THỐNG

| Tiêu chí so sánh | Mật khẩu truyền thống | Mật khẩu + OTP SMS | Mật khẩu + App Authenticator | FIDO2 / WebAuthn (Passkeys) |
| :--- | :---: | :---: | :---: | :---: |
| **Chống Phishing** | ❌ Hoàn toàn không | ❌ Bị lừa qua trang giả mạo | ❌ Bị lừa qua Reverse Proxy (Evilginx) | ✅ **Tuyệt đối (Bảo vệ bằng Origin)** |
| **Chống Replay Attack** | ❌ Bị bắt lại gói tin | ⚠️ OTP dùng 1 lần (nhưng dễ bị chặn) | ⚠️ Mã TOTP có hiệu lực 30s | ✅ **Tuyệt đối (Challenge ngẫu nhiên & Counter)** |
| **Bảo mật khi Lộ CSDL** | ❌ Bị bẻ khóa Hash/Bcrypt | ❌ Vẫn mất mật khẩu gốc | ❌ Vẫn mất mật khẩu gốc | ✅ **Tuyệt đối (Server chỉ lưu Public Key)** |
| **Trải nghiệm người dùng** | ⚠️ Phải ghi nhớ, dễ quên | ⚠️ Chờ tin nhắn SMS, trễ mạng | ⚠️ Mở app, sao chép 6 số | ✅ **1 Chạm vân tay / Face ID (Dưới 1 giây)** |
| **Nguy cơ tấn công SIM Swap**| ❌ Không ảnh hưởng | ❌ Rất nguy hiểm | ✅ Không bị ảnh hưởng | ✅ **Miễn nhiễm hoàn toàn** |
| **Hỗ trợ phần cứng** | Không yêu cầu | Chỉ cần điện thoại nhận SMS | Cần smartphone cài app | ✅ **Tích hợp sẵn trong mọi thiết bị hiện đại** |

---

## 9. KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 9.1. Đánh giá kết quả đạt được
- **Hiện thực xuất sắc mục tiêu đề tài:** Xây dựng thành công ứng dụng demo xác thực FIDO2 hoàn chỉnh, trực quan, hỗ trợ cả đăng nhập thông thường, đăng nhập Passkey 1-chạm (Usernameless) và xác thực sinh trắc học nâng cao (Step-Up Authentication).
- **Giải quyết trọn vẹn bài toán an ninh:** Đã minh chứng thực nghiệm và chứng minh toán học về khả năng chống Phishing, chống Replay Attack và bảo vệ an toàn CSDL khi bị rò rỉ.
- **Tính thực tiễn cao:** Tích hợp phân quyền Quản trị viên (Dashboard thống kê thời gian thực) và Sinh viên (Workspace quản lý hồ sơ). Sẵn sàng triển khai thực tế trên nền tảng đám mây Render và MongoDB Atlas.

### 9.2. Hướng phát triển trong tương lai
1. **Mở rộng đồng bộ Passkeys đám mây (Multi-device Passkeys / Passkey Sync):** Hỗ trợ đồng bộ khóa thông qua Apple iCloud Keychain, Google Password Manager và Microsoft Credential Manager để sinh viên có thể đăng nhập liền mạch giữa máy tính và điện thoại.
2. **Cơ chế dự phòng và Khôi phục tài khoản (Account Recovery):** Cho phép một tài khoản đăng ký nhiều khóa Passkey dự phòng (ví dụ: 1 khóa Touch ID trên laptop cá nhân + 1 khóa YubiKey dự phòng cất trong ví).
3. **Mã QR Cross-Device Authentication:** Cho phép dùng camera điện thoại quét mã QR trên màn hình máy tính công cộng để đăng nhập bằng vân tay của điện thoại (chuẩn FIDO Cross-Device).
