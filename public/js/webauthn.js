/**
 * public/js/webauthn.js - Xử lý gọi API Backend và tương tác thư viện WebAuthn
 */

// ==========================================
// 1. LUỒNG ĐĂNG KÝ PASSKEY (SIGN UP)
// ==========================================
export async function handleRegister(username, hoTen, ngaySinh, logCallback) {
    // Hỗ trợ linh hoạt dù truyền 2 tham số hay 4 tham số
    if (typeof hoTen === 'function') {
        logCallback = hoTen;
        hoTen = '';
        ngaySinh = '';
    }
    const log = typeof logCallback === 'function' ? logCallback : console.log;

    const { startRegistration } = window.SimpleWebAuthnBrowser || {};
    if (!startRegistration) {
        const errorMsg = "Không tìm thấy thư viện SimpleWebAuthnBrowser!";
        log("❌ " + errorMsg);
        return { success: false, error: errorMsg };
    }

    try {
        log("🟡 Đang gửi yêu cầu xin Challenge từ Server...");
        
        const optionsRes = await fetch('/api/auth/register-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, hoTen, ngaySinh })
        });

        const optionsJSON = await optionsRes.json();
        if (optionsJSON.error) throw new Error(optionsJSON.error);

        log("🟢 Đang mở cảm biến vân tay / Windows Hello...", optionsJSON);
        
        // Hỗ trợ cả 2 dạng tham số của SimpleWebAuthnBrowser
        let attResp;
        try {
            attResp = await startRegistration({ optionsJSON });
        } catch (e) {
            attResp = await startRegistration(optionsJSON);
        }

        log("🔵 Đang gửi chữ ký lên Server kiểm chứng...", attResp);
        const verifyRes = await fetch('/api/auth/register-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: attResp })
        });

        const verifyJSON = await verifyRes.json();
        if (verifyJSON.verified) {
            log("✅ Đăng ký Passkey thành công!");
            return { success: true };
        } else {
            throw new Error(verifyJSON.error || "Xác minh thất bại từ máy chủ.");
        }
    } catch (error) {
        // Kiểm tra nếu lỗi do tắt bảng Windows Hello, hết thời gian chờ hoặc thiết bị không hỗ trợ
        let customMsg = error.message;
        if (
            error.name === 'NotAllowedError' || 
            customMsg.includes('timed out') || 
            customMsg.includes('not allowed')
        ) {
            customMsg = "Không thể mở xác thực vui lòng kiểm tra lại";
        }

        log("❌ " + customMsg);
        return { success: false, error: customMsg };
    }
}

// ==========================================
// 2. LUỒNG ĐĂNG NHẬP PASSKEY (LOGIN)
// ==========================================
export async function handleLogin(username, logCallback) {
    const log = typeof logCallback === 'function' ? logCallback : console.log;

    const { startAuthentication } = window.SimpleWebAuthnBrowser || {};
    if (!startAuthentication) {
        const errorMsg = "Không tìm thấy thư viện SimpleWebAuthnBrowser!";
        log("❌ " + errorMsg);
        return { success: false, error: errorMsg };
    }

    try {
        log("🟡 Đang gửi yêu cầu xin Challenge đăng nhập...");
        
        const optionsRes = await fetch('/api/auth/login-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const optionsJSON = await optionsRes.json();
        
        if (optionsRes.status === 404) {
            throw new Error("Tài khoản này chưa có Passkey. Vui lòng bấm Sign Up trước!");
        }
        if (optionsJSON.error) throw new Error(optionsJSON.error);
        
        log("🟢 Đang yêu cầu xác thực...", optionsJSON);
        
        let asseResp;
        try {
            asseResp = await startAuthentication({ optionsJSON });
        } catch (e) {
            asseResp = await startAuthentication(optionsJSON);
        }
        
        log("🔵 Đang gửi chữ ký sinh trắc học lên Server...", asseResp);
        
        const verifyRes = await fetch('/api/auth/login-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: asseResp })  
        });
        
        const verifyJSON = await verifyRes.json();
        
        if (verifyJSON.verified) {
            log("✅ Đăng nhập thành công!");
            return { success: true, user: verifyJSON.user, userInfo: verifyJSON.user };
        } else {
            throw new Error(verifyJSON.error || "Chữ ký sinh trắc học không hợp lệ.");
        }
    } catch (error) {
        let customMsg = error.message;
        if (
            error.name === 'NotAllowedError' || 
            customMsg.includes('timed out') || 
            customMsg.includes('not allowed')
        ) {
            customMsg = "Không thể mở xác thực vui lòng kiểm tra lại";
        }

        log("❌ " + customMsg);
        return { success: false, error: customMsg };
    }
}

// ==========================================
// 3. LUỒNG ĐĂNG XUẤT (LOGOUT)
// ==========================================
export async function handleLogout(logCallback) {
    const log = typeof logCallback === 'function' ? logCallback : console.log;
    try {
        await fetch('/api/auth/logout', { method: 'POST' });
        log("✅ Đã đăng xuất an toàn.");
        return { success: true };
    } catch (error) {
        return { success: true };
    }
}

// ==========================================
// 4. LUỒNG XÁC THỰC LẠI (STEP-UP AUTH) ĐỂ HỦY LIÊN KẾT THẺ
// ==========================================
export async function handleStepUpUnlinkCard(logCallback) {
    const log = typeof logCallback === 'function' ? logCallback : console.log;
    const { startAuthentication } = window.SimpleWebAuthnBrowser || {};
    if (!startAuthentication) {
        const errorMsg = "Không tìm thấy thư viện SimpleWebAuthnBrowser!";
        log("❌ " + errorMsg);
        return { success: false, error: errorMsg };
    }

    try {
        log("🟡 Bước 1/3: Đang yêu cầu Server cấp Challenge bảo mật để hủy thẻ...");
        const optionsRes = await fetch('/api/user/profile/unlink-card-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const optionsJSON = await optionsRes.json();
        if (optionsRes.status === 401) {
            throw new Error("Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại!");
        }
        if (optionsJSON.error) {
            throw new Error(optionsJSON.error);
        }

        log("🟢 Bước 2/3: Đã nhận Challenge. Mời quét vân tay / Face ID / Windows Hello để xác thực...");
        let asseResp;
        try {
            asseResp = await startAuthentication({ optionsJSON });
        } catch (e) {
            asseResp = await startAuthentication(optionsJSON);
        }

        log("🔵 Bước 3/3: Đã tạo chữ ký sinh trắc học, đang gửi Server kiểm tra...");
        const verifyRes = await fetch('/api/user/profile/unlink-card-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ response: asseResp })
        });

        const verifyJSON = await verifyRes.json();
        if (verifyRes.ok && verifyJSON.success) {
            log("✅ Xác thực sinh trắc học thành công! Thẻ sinh viên đã được hủy an toàn.");
            return { success: true, profile: verifyJSON.profile };
        } else {
            throw new Error(verifyJSON.error || "Xác thực danh tính thất bại. Không thể hủy liên kết thẻ!");
        }
    } catch (error) {
        let customMsg = error.message;
        if (
            error.name === 'NotAllowedError' || 
            customMsg.includes('timed out') || 
            customMsg.includes('not allowed')
        ) {
            customMsg = "Không thể mở xác thực vui lòng kiểm tra lại";
        }
        log("❌ [HỦY THẺ THẤT BẠI]: " + customMsg);
        return { success: false, error: customMsg };
    }
}
