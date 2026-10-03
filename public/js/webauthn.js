/**
 * public/js/webauthn.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 3 (Frontend FIDO2)
 * 
 * ==============================================================================
 * NHIỆM VỤ CỦA THÀNH VIÊN 3:
 * Tương tác với WebAuthn Browser API và thư viện `@simplewebauthn/browser`
 * ==============================================================================
 * 
 * Thư viện `@simplewebauthn/browser` được nhúng vào file index.html qua thẻ script:
 * window.SimpleWebAuthnBrowser (có sẵn các hàm startRegistration, startAuthentication).
 * 
 * 1. LUỒNG ĐĂNG KÝ (registerUser):
 *    - Bước 1: Gửi tên `username` lên API: POST /api/auth/register-options
 *    - Bước 2: Nhận về gói tin optionsJSON từ Server.
 *    - Bước 3: Gọi hàm của thư viện:
 *              const attResp = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
 *              (Lệnh này sẽ làm máy tính/điện thoại bật hộp thoại quét vân tay TouchID / Windows Hello)
 *    - Bước 4: Gửi kết quả `attResp` ngược lên API: POST /api/auth/register-verify để Server kiểm tra.
 *    - Bước 5: Báo cho giao diện biết kết quả thành công hay thất bại.
 * 
 * 2. LUỒNG ĐĂNG NHẬP (loginUser):
 *    - Bước 1: Gửi tên `username` lên API: POST /api/auth/login-options
 *    - Bước 2: Nhận về gói tin optionsJSON từ Server.
 *    - Bước 3: Gọi hàm của thư viện:
 *              const asseResp = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
 *              (Lệnh này yêu cầu người dùng chạm vân tay để ký vào Challenge)
 *    - Bước 4: Gửi kết quả `asseResp` lên API: POST /api/auth/login-verify.
 *    - Bước 5: Đăng nhập thành công!
 */

// TODO: Thành viên 3 sẽ viết 2 hàm chính:
// export async function handleRegister(username) { ... }
// export async function handleLogin(username) { ... }
