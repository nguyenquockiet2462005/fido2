/**
 * public/js/webauthn.js - TƯƠNG THÍCH HOÀN HẢO VỚI SERVER HIỆN TẠI
 */

const getStartRegistration = () => window.SimpleWebAuthnBrowser?.startRegistration;
const getStartAuthentication = () => window.SimpleWebAuthnBrowser?.startAuthentication;

// 1. LUỒNG ĐĂNG KÝ PASSKEY
export async function handleRegister(username, logCallback) {
    try {
        const startRegistration = getStartRegistration();
        if (!startRegistration) throw new Error("Chưa nạp xong thư viện SimpleWebAuthnBrowser. Vui lòng thử lại!");

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
        if (verifyRes.ok && (verifyJSON.verified !== false)) {
            logCallback("✅ Bước 4: Xác minh thành công! Đã lưu Passkey mới.");
            return { success: true };
        } else {
            throw new Error(verifyJSON.error || "Xác minh thất bại từ máy chủ.");
        }
    } catch (error) {
        logCallback("❌ Lỗi Đăng ký: " + error.message);
        return { success: false, error: error.message };
    }
}

// 2. LUỒNG ĐĂNG NHẬP PASSKEY
export async function handleLogin(username, logCallback) {
    try {
        const startAuthentication = getStartAuthentication();
        if (!startAuthentication) throw new Error("Chưa nạp xong thư viện SimpleWebAuthnBrowser. Vui lòng thử lại!");

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
        
        if (verifyRes.ok && !verifyJSON.error) {
            logCallback("✅ Bước 4: Đăng nhập thành công! Đã cấp quyền truy cập.");
            return { success: true };
        } else {
            throw new Error(verifyJSON.error || "Chữ ký sinh trắc học không hợp lệ.");
        }
    } catch (error) {
        logCallback("❌ Lỗi Đăng nhập: " + error.message);
        return { success: false, error: error.message };
    }
}

// 3. LUỒNG ĐĂNG XUẤT (LOGOUT)
export async function handleLogout(logCallback) {
    try {
        logCallback("🟡 Đang gửi yêu cầu đăng xuất tới Server...");
        await fetch('/api/auth/logout', { method: 'POST' });
        logCallback("✅ Đã hủy phiên đăng nhập an toàn.");
        return { success: true };
    } catch (error) {
        logCallback("⚠️ Đăng xuất cục bộ: " + error.message);
        return { success: true };
    }
}

// 4. LẤY DANH SÁCH PASSKEY CỦA USER
export async function fetchUserPasskeys(username) {
    try {
        const res = await fetch(`/api/auth/passkeys?username=${encodeURIComponent(username)}`);
        if (!res.ok) return [];
        const data = await res.json();
        return data.passkeys || [];
    } catch (error) {
        return [];
    }
}