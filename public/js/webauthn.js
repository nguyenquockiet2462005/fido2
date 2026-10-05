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

/**
 * public/js/webauthn.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 3 (Frontend FIDO2)
 */

// Lấy 2 hàm cốt lõi từ thư viện đã được nhúng ở file index.html
const { startRegistration, startAuthentication } = window.SimpleWebAuthnBrowser;

// =========================================================================
// 1. LUỒNG ĐĂNG KÝ VÂN TAY / FACE ID (registerUser)
// =========================================================================
export async function handleRegister(username) {
    try {
        console.log(`[Đăng ký] Bắt đầu lấy options cho user: ${username}...`);
        
        // Bước 1: Gửi tên `username` lên API để xin Challenge
        const optionsRes = await fetch('/api/auth/register-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        if (!optionsRes.ok) throw new Error('Lỗi khi lấy Registration Options từ Server');

        // Bước 2: Nhận về gói tin optionsJSON từ Server
        const optionsJSON = await optionsRes.json();

        // Bước 3: Gọi hàm của thư viện để bật Windows Hello / TouchID
        console.log('[Đăng ký] Đang chờ người dùng quét vân tay/khuôn mặt...');
        let attResp;
        try {
            attResp = await startRegistration({ optionsJSON });
        } catch (error) {
            // Lỗi này xảy ra nếu người dùng bấm nút "Cancel" hoặc máy tính không có cảm biến
            throw new Error('Người dùng đã hủy hoặc thiết bị không hỗ trợ bảo mật sinh trắc học.');
        }

        // Bước 4: Gửi kết quả (chữ ký) ngược lên API để Server kiểm tra
        console.log('[Đăng ký] Quét thành công, đang gửi chữ ký lên Server xác minh...');
        const verifyRes = await fetch('/api/auth/register-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // Tùy theo code của Backend, thường sẽ gửi kèm username và bản chữ ký
            body: JSON.stringify({ username, response: attResp }) 
        });

        // Bước 5: Báo cho giao diện biết kết quả
        const verifyJSON = await verifyRes.json();
        if (verifyJSON.verified) {
            return { success: true, message: 'Đăng ký vân tay/khuôn mặt thành công!' };
        } else {
            return { success: false, message: 'Xác minh đăng ký thất bại từ phía Server.' };
        }

    } catch (error) {
        console.error('[Lỗi Đăng ký]:', error);
        return { success: false, message: error.message };
    }
}


// =========================================================================
// 2. LUỒNG ĐĂNG NHẬP (loginUser)
// =========================================================================
export async function handleLogin(username) {
    try {
        console.log(`[Đăng nhập] Bắt đầu lấy options cho user: ${username}...`);
        
        // Bước 1: Gửi tên `username` lên API để lấy Challenge
        const optionsRes = await fetch('/api/auth/login-options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!optionsRes.ok) throw new Error('Lỗi khi lấy Authentication Options từ Server');

        // Bước 2: Nhận về gói tin optionsJSON từ Server
        const optionsJSON = await optionsRes.json();

        // Bước 3: Gọi hàm của thư viện để yêu cầu người dùng quét vân tay
        console.log('[Đăng nhập] Đang chờ người dùng quét vân tay/khuôn mặt để đăng nhập...');
        let asseResp;
        try {
            asseResp = await startAuthentication({ optionsJSON });
        } catch (error) {
            throw new Error('Đăng nhập bị hủy hoặc vân tay không chính xác.');
        }

        // Bước 4: Gửi kết quả chữ ký lên API xác minh
        console.log('[Đăng nhập] Đã lấy được chữ ký, đang gửi lên Server xác minh...');
        const verifyRes = await fetch('/api/auth/login-verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, response: asseResp })
        });

        // Bước 5: Báo cáo kết quả đăng nhập!
        const verifyJSON = await verifyRes.json();
        if (verifyJSON.verified) {
            return { success: true, message: 'Đăng nhập thành công!' };
        } else {
            return { success: false, message: 'Xác minh đăng nhập thất bại. Vui lòng thử lại.' };
        }

    } catch (error) {
        console.error('[Lỗi Đăng nhập]:', error);
        return { success: false, message: error.message };
    }
}