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
import { handleRegister, handleLogin, handleLogout } from './webauthn.js';
import { scanStudentCardDual } from './scanner.js';

// 2. Lấy các phần tử giao diện từ DOM
const outputLog = document.getElementById('outputLog');
const guestView = document.getElementById('guest-view');
const dashboardView = document.getElementById('dashboard-view');

const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const btnLogout = document.getElementById('btn-logout');

const inputUsername = document.getElementById('username');
const welcomeMessage = document.getElementById('welcome-message');

// Các phần tử Thẻ Sinh Viên
const studentCard = document.getElementById('student-card');
const cardAvatar = document.getElementById('card-avatar');
const cardVerifyBadge = document.getElementById('card-verify-badge');
const cardFullName = document.getElementById('card-fullname');
const cardMssv = document.getElementById('card-mssv');
const cardDob = document.getElementById('card-dob');
const cardYear = document.getElementById('card-year');
const cardFaculty = document.getElementById('card-faculty');

const btnScanCard = document.getElementById('btn-scan-card');
const cardFileInput = document.getElementById('card-file-input');


let currentLoggedInUser = '';


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
// function setButtonsLoading(isLoading) {
//     btnRegister.disabled = isLoading;
//     btnLogin.disabled = isLoading;
//     btnRegister.style.opacity = isLoading ? '0.6' : '1';
//     btnLogin.style.opacity = isLoading ? '0.6' : '1';
//     btnRegister.style.cursor = isLoading ? 'not-allowed' : 'pointer';
//     btnLogin.style.cursor = isLoading ? 'not-allowed' : 'pointer';
// }

function setButtonsLoading(isLoading) {
    if (btnRegister) {
        btnRegister.disabled = isLoading;
        btnRegister.style.opacity = isLoading ? '0.6' : '1';
        btnRegister.style.cursor = isLoading ? 'not-allowed' : 'pointer';
    }
    if (btnLogin) {
        btnLogin.disabled = isLoading;
        btnLogin.style.opacity = isLoading ? '0.6' : '1';
        btnLogin.style.cursor = isLoading ? 'not-allowed' : 'pointer';
    }
}

// ==========================================
// BẮT SỰ KIỆN NÚT BẤM
// ==========================================


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
            logToInspector("🔓 Đã xác thực danh tính an toàn với FIDO2 Passkey!");// Chuyển sang màn hình chào mừng
            switchView(true, username);
        }
    } catch (error) {
        logToInspector(`❌ Lỗi ngoài ý muốn: ${error.message}`);
    } finally {
        setButtonsLoading(false);
    }
});

// 3. Nút Đăng xuất
btnLogout.addEventListener('click', async () => {
    logToInspector(`[Đăng xuất] Đã đăng xuất tài khoản: ${currentLoggedInUser}`, true);
    try {
        await handleLogout(logToInspector);
    } catch (e) {
        // Bỏ qua lỗi backend nếu API chưa có
    }
    switchView(false);
});

// Hàm gọi API lấy hồ sơ và render lên Thẻ Sinh Viên
async function loadUserProfile() {
    try {
        const res = await fetch('/api/user/profile');
        if (!res.ok) return;
        const data = await res.json();
        const profile = data.profile || {};

        // 1. Điền tên tài khoản dưới avatar
        const cardUserEl = document.getElementById('card-username');
        if (cardUserEl) cardUserEl.innerText = `@${data.username || currentLoggedInUser}`;

        // 2. Điền thông tin sinh viên
        if (cardFullName) cardFullName.innerText = profile.fullName || data.username;
        if (cardMssv) cardMssv.innerText = profile.studentId || '(Chưa liên kết)';
        if (cardDob) cardDob.innerText = profile.dob || '--/--/----';
        if (cardAvatar && profile.avatar) cardAvatar.src = profile.avatar;

        const rowYear = document.getElementById('row-year');
        const securityStatus = document.getElementById('card-security-status');

        // 3. Trạng thái xác thực ở góc dưới bên phải
        if (profile.isVerifiedCard) {
            studentCard.classList.remove('unverified');
            studentCard.classList.add('verified');

            // Hiện dòng Khóa khi đã xác thực
            if (rowYear) {
                rowYear.style.display = 'flex';
                if (cardYear) cardYear.innerText = profile.academicYear || '';
            }

            // Góc dưới bên phải: "Đã xác thực" màu xanh lá
            if (securityStatus) {
                securityStatus.innerText = 'Đã xác thực';
                securityStatus.style.color = 'var(--success)';
            }
        } else {
            studentCard.classList.remove('verified');
            studentCard.classList.add('unverified');

            // Ẩn dòng Khóa khi chưa quét thẻ
            if (rowYear) {
                rowYear.style.display = 'none';
            }

            // Góc dưới bên phải: "Chưa xác thực" màu xám
            if (securityStatus) {
                securityStatus.innerText = 'Chưa xác thực';
                securityStatus.style.color = 'var(--text-muted)';
            }
        }
    } catch (err) {
        console.error("Lỗi khi tải hồ sơ:", err);
    }
}


function switchView(isLoggedIn, username = '') {
    if (isLoggedIn) {
        currentLoggedInUser = username;
        guestView.classList.add('hidden');
        dashboardView.classList.remove('hidden');
        // 👉 GỌI TẢI HỒ SƠ LÊN THẺ KHI ĐĂNG NHẬP THÀNH CÔNG:
        loadUserProfile();
    } else {
        currentLoggedInUser = '';
        dashboardView.classList.add('hidden');
        guestView.classList.remove('hidden');
    }
}
// ==========================================
// SỰ KIỆN: QUÉT THẺ SINH VIÊN KÉP (DUAL-SCAN)
// ==========================================
if (btnScanCard && cardFileInput) {
    // 1. Khi bấm nút, mở cửa sổ chọn ảnh hoặc mở camera
    btnScanCard.addEventListener('click', () => {
        cardFileInput.click();
    });

    // 2. Khi người dùng đã chụp hoặc chọn ảnh thẻ sinh viên HUTECH
    cardFileInput.addEventListener('change', async (event) => {
        const file = event.target.files && event.target.files[0];
        if (!file) return;

        logToInspector(`[DUAL-SCAN] Bắt đầu phân tích hình ảnh thẻ: ${file.name}...`, true);
        btnScanCard.disabled = true;
        btnScanCard.innerText = "Đang quét thẻ sinh viên...";

        try {
            // Bước A: Quét song song QR và OCR từ file
            const cardData = await scanStudentCardDual(file, (stepMsg) => {
                logToInspector(stepMsg);
            });

            logToInspector(`[KẾT QUẢ QUÉT] MSSV: ${cardData.studentId} | Họ tên: ${cardData.fullName}`);
            logToInspector("🟡 Đang gửi bằng chứng vật lý lên Server để xác thực chính chủ...");

            // Bước B: Gửi dữ liệu thẻ lên Backend
            const res = await fetch('/api/user/profile/verify-card', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cardData)
            });

            const resData = await res.json();

            if (res.ok && resData.success) {
                logToInspector("✅ [XÁC THỰC THÀNH CÔNG] Thẻ sinh viên HUTECH đã được gắn vào tài khoản!");

                // Nếu vừa thu hồi từ một tài khoản mạo danh trước đó
                if (resData.revokedFakeAccount) {
                    logToInspector(`🚨 [THU HỒI DANH TÍNH] Đã phát hiện và xóa tài khoản mạo danh: "${resData.revokedFakeAccount}"!`);
                }

                // Tải lại giao diện Thẻ sinh viên sang màu xanh lá chính chủ
                await loadUserProfile();
                alert(`Chúc mừng! Thẻ sinh viên ${cardData.studentId} đã được xác thực chính chủ thành công!`);
            } else {
                throw new Error(resData.error || "Xác thực thẻ thất bại từ máy chủ.");
            }
        } catch (error) {
            logToInspector(`❌ [LỖI XÁC THỰC THẺ]: ${error.message}`);
            alert(error.message);
        } finally {
            btnScanCard.disabled = false;
            btnScanCard.innerText = "Quét Thẻ Sinh Viên";
            cardFileInput.value = ''; // Reset input để có thể quét lại lần sau
        }
    });
}

