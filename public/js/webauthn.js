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

        let optionsJSON;
        try {
            optionsJSON = await optionsRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối máy chủ (${optionsRes.status}). Vui lòng thử lại!`);
        }
        if (!optionsRes.ok || optionsJSON.error) {
            throw new Error(optionsJSON?.error || `Lỗi từ máy chủ (${optionsRes.status})`);
        }

        log("🟢 Đang yêu cầu xác thực sinh trắc học...", optionsJSON);

        // Gọi xác thực tạo khóa Passkey với thư viện SimpleWebAuthnBrowser v14
        const attResp = await startRegistration({ optionsJSON });

        log("🔵 Đang gửi chữ ký lên Server kiểm chứng...", attResp);
        const verifyRes = await fetch('/api/auth/register-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: attResp })
        });

        let verifyJSON;
        try {
            verifyJSON = await verifyRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối khi xác thực (${verifyRes.status})`);
        }
        if (verifyJSON.verified) {
            log("✅ Đăng ký Passkey thành công!");
            return { success: true };
        } else {
            throw new Error(verifyJSON.error || "Xác minh thất bại từ máy chủ.");
        }
    } catch (error) {
        let customMsg = error.message;
        if (
            error.name === 'NotAllowedError' ||
            customMsg.includes('timed out') ||
            customMsg.includes('not allowed')
        ) {
            customMsg = "Đã hủy thao tác xác thực sinh trắc học.";
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

        let optionsJSON;
        try {
            optionsJSON = await optionsRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối máy chủ (${optionsRes.status}). Vui lòng thử lại!`);
        }

        if (optionsRes.status === 404) {
            throw new Error("Tài khoản này chưa có Passkey. Vui lòng bấm Đăng Kí trước!");
        }
        if (!optionsRes.ok || optionsJSON.error) {
            throw new Error(optionsJSON?.error || `Lỗi từ máy chủ (${optionsRes.status})`);
        }

        log("🟢 Đang yêu cầu xác thực...", optionsJSON);

        // Gọi xác thực đăng nhập một lần duy nhất với cấu trúc optionsJSON chuẩn
        const asseResp = await startAuthentication({ optionsJSON });

        log("🔵 Đang gửi chữ ký sinh trắc học lên Server...", asseResp);

        const verifyRes = await fetch('/api/auth/login-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: asseResp })
        });

        let verifyJSON;
        try {
            verifyJSON = await verifyRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối khi xác thực (${verifyRes.status})`);
        }

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
            customMsg = "Đã hủy thao tác xác thực sinh trắc học.";
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

        let optionsJSON;
        try {
            optionsJSON = await optionsRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối máy chủ (${optionsRes.status}). Vui lòng thử lại!`);
        }
        if (optionsRes.status === 401) {
            throw new Error("Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại!");
        }
        if (!optionsRes.ok || optionsJSON.error) {
            throw new Error(optionsJSON?.error || `Lỗi máy chủ (${optionsRes.status})`);
        }

        log("🟢 Bước 2/3: Đã nhận Challenge. Mời quét vân tay / Face ID / Windows Hello để xác thực...");
        const asseResp = await startAuthentication({ optionsJSON });

        log("🔵 Bước 3/3: Đã tạo chữ ký sinh trắc học, đang gửi Server kiểm tra...");
        const verifyRes = await fetch('/api/user/profile/unlink-card-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ response: asseResp })
        });

        let verifyJSON;
        try {
            verifyJSON = await verifyRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối máy chủ khi hủy thẻ (${verifyRes.status})`);
        }
        if (verifyRes.ok && verifyJSON.success) {
            log("✅ Xác thực sinh trắc học thành công! Thẻ sinh viên đã được hủy an toàn.");
            return { success: true, profile: verifyJSON.profile };
        } else {
            throw new Error(verifyJSON?.error || "Xác thực danh tính thất bại. Không thể hủy liên kết thẻ!");
        }
    } catch (error) {
        let customMsg = error.message;
        if (
            error.name === 'NotAllowedError' ||
            customMsg.includes('timed out') ||
            customMsg.includes('not allowed')
        ) {
            customMsg = "Đã hủy thao tác xác thực sinh trắc học.";
        }
        log("❌ [HỦY THẺ THẤT BẠI]: " + customMsg);
        return { success: false, error: customMsg };
    }
}
