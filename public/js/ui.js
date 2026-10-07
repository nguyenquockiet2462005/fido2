/**
 * public/js/ui.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 4 (UI Controller & Inspector)
 * 
 * ==============================================================================
 * VAI TRÒ CHÍNH:
 * 1. Quản lý DOM (bắt sự kiện nút bấm, đọc input username, vô hiệu hóa nút khi xử lý).
 * 2. Gọi các hàm nghiệp vụ FIDO2 do Thành viên 3 (Huy) phụ trách trong `webauthn.js`.
 * 3. Hiển thị thông báo và tiến trình trực quan trên màn hình Live Security Inspector.
 * ==============================================================================
 */

// 1. Nhập (Import) 2 hàm xử lý FIDO2 từ file của Thành viên 3 (Huy)
import { handleRegister, handleLogin } from './webauthn.js';

// 2. Lấy các phần tử giao diện từ DOM
const outputLog = document.getElementById('outputLog');
const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const inputUsername = document.getElementById('username');

// 3. Hàm hỗ trợ in thông điệp ra Live Security Inspector
export function logToInspector(message, isReset = false) {
    if (!outputLog) return;
    if (isReset) {
        outputLog.innerText = message + '\n';
    } else {
        outputLog.innerText += message + '\n';
    }
    // Tự động cuộn xuống dòng mới nhất
    outputLog.scrollTop = outputLog.scrollHeight;
}

// 4. Hàm khóa/mở nút bấm khi đang thực hiện quét vân tay (tránh người dùng bấm liên tục)
function setButtonsLoading(isLoading) {
    btnRegister.disabled = isLoading;
    btnLogin.disabled = isLoading;
    btnRegister.style.opacity = isLoading ? '0.6' : '1';
    btnLogin.style.opacity = isLoading ? '0.6' : '1';
    btnRegister.style.cursor = isLoading ? 'not-allowed' : 'pointer';
    btnLogin.style.cursor = isLoading ? 'not-allowed' : 'pointer';
}

// ==========================================
// SỰ KIỆN: BẤM NÚT "ĐĂNG KÝ PASSKEY"
// ==========================================
btnRegister.addEventListener('click', async () => {
    const username = inputUsername.value.trim();
    if (!username) {
        alert("Vui lòng nhập tên người dùng!");
        inputUsername.focus();
        return;
    }

    logToInspector(`[Đăng ký] Bắt đầu tạo Passkey cho tài khoản: ${username}`, true);
    setButtonsLoading(true);

    try {
        // Ủy thác cho hàm của Huy trong webauthn.js thực hiện, truyền kèm hàm logToInspector
        const result = await handleRegister(username, logToInspector);
        if (result && result.success) {
            logToInspector("🎉 Chúc mừng! Bạn có thể thử Đăng nhập ngay bây giờ.");
        }
    } catch (error) {
        logToInspector(`❌ Lỗi ngoài ý muốn: ${error.message}`);
    } finally {
        setButtonsLoading(false);
    }
});

// ==========================================
// SỰ KIỆN: BẤM NÚT "ĐĂNG NHẬP PASSKEY"
// ==========================================
btnLogin.addEventListener('click', async () => {
    const username = inputUsername.value.trim();
    if (!username) {
        alert("Vui lòng nhập tên người dùng!");
        inputUsername.focus();
        return;
    }

    logToInspector(`[Đăng nhập] Bắt đầu xác thực cho tài khoản: ${username}`, true);
    setButtonsLoading(true);

    try {
        // Ủy thác cho hàm của Huy trong webauthn.js thực hiện, truyền kèm hàm logToInspector
        const result = await handleLogin(username, logToInspector);
        if (result && result.success) {
            logToInspector("🔓 Đã xác thực danh tính an toàn với FIDO2 Passkey!");
        }
    } catch (error) {
        logToInspector(`❌ Lỗi ngoài ý muốn: ${error.message}`);
    } finally {
        setButtonsLoading(false);
    }
});