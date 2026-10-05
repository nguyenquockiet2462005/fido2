/**
 * public/js/webauthn.js - KHÔNG GIAN LÀM VIỆC CỦA HUY (Frontend FIDO2)
 * Nhiệm vụ: Chuyên xử lý logic gọi API Backend và tương tác thư viện WebAuthn
 */

const { startRegistration, startAuthentication } = window.SimpleWebAuthnBrowser;

// ==========================================
// 1. LUỒNG ĐĂNG KÝ PASSKEY
// ==========================================
export async function handleRegister(username, logCallback) {
    try {
        logCallback("🟡 Bước 1: Đang gửi yêu cầu xin Challenge từ Server...");
        const optionsRes = await fetch('/api/auth/register-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const optionsJSON = await optionsRes.json();
        if (optionsJSON.error) throw new Error(optionsJSON.error);

        logCallback("🟢 Bước 2: Đã nhận Challenge, đang mở cảm biến vân tay/Windows Hello...");
        const attResp = await startRegistration({ optionsJSON });

        logCallback("🔵 Bước 3: Người dùng đã quét xong, đang gửi chữ ký lên Server...");
        const verifyRes = await fetch('/api/auth/register-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: attResp })
        });
        
        const verifyJSON = await verifyRes.json();
        if (verifyJSON.verified) {
            logCallback("✅ Bước 4: Xác minh thành công! Đã lưu Passkey vào Database.");
            return { success: true };
        } else {
            throw new Error(verifyJSON.error || "Xác minh thất bại từ máy chủ.");
        }
    } catch (error) {
        logCallback("❌ Lỗi Đăng ký: " + error.message);
        return { success: false, error: error.message };
    }
}

// ==========================================
// 2. LUỒNG ĐĂNG NHẬP PASSKEY
// ==========================================
export async function handleLogin(username, logCallback) {
    try {
        logCallback("🟡 Bước 1: Đang gửi yêu cầu xin Challenge đăng nhập từ Server...");
        const optionsRes = await fetch('/api/auth/login-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const optionsJSON = await optionsRes.json();
        if (optionsRes.status === 404) {
            throw new Error("Tài khoản này chưa có Passkey. Vui lòng đăng ký trước!");
        }
        if (optionsJSON.error) throw new Error(optionsJSON.error);

        logCallback("🟢 Bước 2: Đã nhận Challenge, đang yêu cầu chạm vân tay...");
        const asseResp = await startAuthentication({ optionsJSON });

        logCallback("🔵 Bước 3: Đã lấy được chữ ký sinh trắc học, đang gửi lên Server...");
        const verifyRes = await fetch('/api/auth/login-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: asseResp })
        });
        
        const verifyJSON = await verifyRes.json();
        if (verifyJSON.verified) {
            logCallback("✅ Bước 4: Đăng nhập thành công! Đã cấp quyền truy cập.");
            return { success: true };
        } else {
            throw new Error("Chữ ký sinh trắc học không hợp lệ.");
        }
    } catch (error) {
        logCallback("❌ Lỗi Đăng nhập: " + error.message);
        return { success: false, error: error.message };
    }
}