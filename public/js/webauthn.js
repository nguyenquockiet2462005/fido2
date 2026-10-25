/**
 * public/js/webauthn.js - Xử lý gọi API Backend và tương tác thư viện WebAuthn
 */

// ==========================================
// 1. LUỒNG ĐĂNG KÝ PASSKEY (SIGN UP)
// ==========================================
export async function handleRegister(username, hoTen, ngaySinh, logCallback, promptTokenCallback) {
    // Hỗ trợ linh hoạt tham số
    if (typeof hoTen === 'function') {
        promptTokenCallback = ngaySinh;
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

        let optionsRes = await fetch('/api/auth/register-options', {
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

        // BẢO MẬT (C2): Khi Server yêu cầu needsAdminToken (Admin chưa có Passkey, đăng ký lần đầu)
        // Gọi callback giao diện được truyền từ UI layer (Clean Code / Inversion of Control)
        if (optionsRes.status === 403 && optionsJSON?.needsAdminToken) {
            const getSetupToken = typeof promptTokenCallback === 'function'
                ? promptTokenCallback
                : () => Promise.resolve(window.prompt("Nhập mã kích hoạt Admin (ADMIN_SETUP_TOKEN):"));

            const setupToken = await getSetupToken();
            if (!setupToken) {
                log("❌ Đã hủy thao tác cài đặt Admin.");
                return { success: false, error: "Đã hủy thao tác cài đặt Admin." };
            }

            // Gửi lại yêu cầu kèm setupToken
            optionsRes = await fetch('/api/auth/register-options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, hoTen, ngaySinh, setupToken })
            });
            try {
                optionsJSON = await optionsRes.json();
            } catch (_) {
                throw new Error(`Lỗi kết nối máy chủ (${optionsRes.status}). Vui lòng thử lại!`);
            }
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
            throw new Error("Tài khoản này chưa được đăng ký!");
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
// 2b. LUỒNG ĐĂNG NHẬP PASSKEY 1-CHẠM (USERNAMELESS)
// ==========================================
export async function handleQuickPasskeyLogin(logCallback) {
    const log = typeof logCallback === 'function' ? logCallback : console.log;
    const { startAuthentication } = window.SimpleWebAuthnBrowser || {};
    if (!startAuthentication) {
        const errorMsg = "Không tìm thấy thư viện SimpleWebAuthnBrowser!";
        log("❌ " + errorMsg);
        return { success: false, error: errorMsg };
    }

    try {
        log("Đang khởi tạo phiên đăng nhập 1-chạm...");
        const optionsRes = await fetch('/api/auth/login-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}) // Không gửi username
        });

        let optionsJSON;
        try {
            optionsJSON = await optionsRes.json();
        } catch (_) {
            throw new Error(`Lỗi máy chủ (${optionsRes.status}). Vui lòng thử lại!`);
        }

        if (!optionsRes.ok || optionsJSON.error) {
            throw new Error(optionsJSON?.error || "Không thể khởi tạo phiên đăng nhập.");
        }

        log("Vui lòng chạm vân tay hoặc quét Face ID...");
        const asseResp = await startAuthentication({ optionsJSON });

        log("Đang xác thực chữ ký bảo mật...");
        const verifyRes = await fetch('/api/auth/login-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ response: asseResp }) // Không gửi username
        });

        let verifyJSON;
        try {
            verifyJSON = await verifyRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối máy chủ (${verifyRes.status})`);
        }

        if (verifyRes.ok && verifyJSON.verified) {
            log(`Đăng nhập thành công! Xin chào ${verifyJSON.user?.username || ''}`);
            return { success: true, user: verifyJSON.user };
        } else {
            throw new Error(verifyJSON?.error || "Xác thực Passkey thất bại.");
        }
    } catch (error) {
        let customMsg = error.message;
        if (
            error.name === 'NotAllowedError' ||
            customMsg.includes('timed out') ||
            customMsg.includes('not allowed')
        ) {
            customMsg = "Đã hủy thao tác xác thực Passkey.";
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
// 4. LUỒNG XÁC THỰC NÂNG CAO (STEP-UP AUTH) ĐỂ CẬP NHẬT HỒ SƠ SINH VIÊN
// ==========================================
export async function handleStepUpUpdateProfile(profileData, logCallback) {
    const log = typeof logCallback === 'function' ? logCallback : console.log;
    const { startAuthentication } = window.SimpleWebAuthnBrowser || {};
    if (!startAuthentication) {
        const errorMsg = "Không tìm thấy thư viện SimpleWebAuthnBrowser!";
        log("❌ " + errorMsg);
        return { success: false, error: errorMsg };
    }

    try {
        log("Đang chuẩn bị phiên xác thực...");
        const optionsRes = await fetch('/api/user/profile/step-up-options', {
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

        log("Vui lòng chạm vân tay hoặc quét Face ID để xác nhận...");
        const asseResp = await startAuthentication({ optionsJSON });

        log("Đang xác thực chữ ký bảo mật...");
        const verifyRes = await fetch('/api/user/profile/step-up-update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                response: asseResp,
                profileData
            })
        });

        let verifyJSON;
        try {
            verifyJSON = await verifyRes.json();
        } catch (_) {
            throw new Error(`Lỗi kết nối máy chủ khi cập nhật hồ sơ (${verifyRes.status})`);
        }
        if (verifyRes.ok && verifyJSON.success) {
            log("Cập nhật thông tin sinh viên thành công!");
            return { success: true, profile: verifyJSON.profile, message: verifyJSON.message };
        } else {
            throw new Error(verifyJSON?.error || "Xác thực danh tính thất bại. Không thể cập nhật hồ sơ!");
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

        if (customMsg.includes("Đã hủy")) {
            log("ℹ️ " + customMsg);
        } else {
            log("❌ " + customMsg);
        }
        return { success: false, error: customMsg };
    }
}

