/**
 * public/js/ui.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 4 (UI Controller & Inspector)
 * 
 * ==============================================================================
 * NHIỆM VỤ CỦA THÀNH VIÊN 4:
 * Quản lý giao diện, bắt sự kiện nút bấm và hiển thị luồng dữ liệu bảo mật (Live Inspector)
 * ==============================================================================
 * 
 * 1. Bắt sự kiện:
 *    - Khi người dùng bấm nút "Đăng Ký bằng Passkey" -> Lấy username từ ô input, gọi hàm handleRegister() của Người 3.
 *    - Khi người dùng bấm nút "Đăng Nhập bằng Passkey" -> Gọi hàm handleLogin() của Người 3.
 * 
 * 2. Hộp thoại Live Security Inspector (Điểm nhấn khi báo cáo môn học):
 *    - In từng bước ra màn hình console trực quan trên web:
 *      + Bước 1: 🟡 Đang gửi yêu cầu xin Challenge từ Server...
 *      + Bước 2: 🟢 Đã nhận Challenge, đang mở cảm biến vân tay...
 *      + Bước 3: 🔵 Người dùng đã chạm vân tay, đang gửi chữ ký lên Server...
 *      + Bước 4: ✅ Xác minh thành công! Đã cấp quyền truy cập.
 */

// TODO: Thành viên 4 sẽ viết mã điều khiển giao diện tại đây

/**
 * public/js/ui.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 4 (UI Controller & Inspector)
 */

const { startRegistration, startAuthentication } = window.SimpleWebAuthnBrowser;

const outputLog = document.getElementById('outputLog');
const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const inputUsername = document.getElementById('username');

// Hàm hỗ trợ in log ra màn hình
function logToInspector(message, isReset = false) {
    if (isReset) {
        outputLog.innerText = message + '\n';
    } else {
        outputLog.innerText += message + '\n';
    }
    // Tự động cuộn xuống dòng mới nhất
    outputLog.scrollTop = outputLog.scrollHeight;
}

// ==========================================
// SỰ KIỆN ĐĂNG KÝ PASSKEY
// ==========================================
btnRegister.addEventListener('click', async () => {
    const username = inputUsername.value.trim();
    if (!username) return alert("Vui lòng nhập tên người dùng!");

    logToInspector(`[Đăng ký] Bắt đầu tạo Passkey cho tài khoản: ${username}`, true);

    try {
        logToInspector("🟡 Bước 1: Đang gửi yêu cầu xin Challenge từ Server...");
        const optionsRes = await fetch('/api/auth/register-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        const optionsJSON = await optionsRes.json();
        if (optionsJSON.error) throw new Error(optionsJSON.error);

        logToInspector("🟢 Bước 2: Đã nhận Challenge, đang mở cảm biến vân tay/Windows Hello...");
        const attResp = await startRegistration({ optionsJSON });

        logToInspector("🔵 Bước 3: Người dùng đã quét xong, đang gửi chữ ký lên Server...");
        const verifyRes = await fetch('/api/auth/register-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: attResp })
        });
        const verifyJSON = await verifyRes.json();

        if (verifyJSON.verified) {
            logToInspector("✅ Bước 4: Xác minh thành công! Đã lưu Passkey vào Database.");
        } else {
            logToInspector("❌ Bước 4: Xác minh thất bại: " + verifyJSON.error);
        }
    } catch (error) {
        logToInspector("❌ Lỗi: " + error.message);
    }
});

// ==========================================
// SỰ KIỆN ĐĂNG NHẬP PASSKEY
// ==========================================
btnLogin.addEventListener('click', async () => {
    const username = inputUsername.value.trim();
    if (!username) return alert("Vui lòng nhập tên người dùng!");

    logToInspector(`[Đăng nhập] Bắt đầu xác thực cho tài khoản: ${username}`, true);

    try {
        logToInspector("🟡 Bước 1: Đang gửi yêu cầu xin Challenge đăng nhập từ Server...");
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

        logToInspector("🟢 Bước 2: Đã nhận Challenge, đang yêu cầu chạm vân tay...");
        const asseResp = await startAuthentication({ optionsJSON });

        logToInspector("🔵 Bước 3: Đã lấy được chữ ký sinh trắc học, đang gửi lên Server...");
        const verifyRes = await fetch('/api/auth/login-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: asseResp })
        });
        const verifyJSON = await verifyRes.json();

        if (verifyJSON.verified) {
            logToInspector("✅ Bước 4: Đăng nhập thành công! Đã cấp quyền truy cập.");
        } else {
            logToInspector("❌ Bước 4: Chữ ký không hợp lệ.");
        }
    } catch (error) {
        logToInspector("❌ Lỗi: " + error.message);
    }
});