/**
 * public/js/ui.js - Điều Khiển Giao Diện Người Dùng & Đồng Bộ Trạng Thái FIDO2
 */

import { handleRegister, handleLogin, handleLogout, handleStepUpUnlinkCard } from './webauthn.js';
import { scanStudentCardDual } from './scanner.js';

// 1. Lấy các phần tử từ DOM
const guestView = document.getElementById('guest-view');
const dashboardView = document.getElementById('dashboard-view');

const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const btnLogout = document.getElementById('btn-logout');

const inputUsername = document.getElementById('username');
const inputHoTen = document.getElementById('hoTen');
const inputNgaySinh = document.getElementById('ngaySinh');
const welcomeMessage = document.getElementById('welcome-message');

// Bảng Pop-up nhỏ dưới 2 nút Login & Sign Up
const inlinePopup = document.getElementById('inline-popup');
const inlinePopupIcon = document.getElementById('inline-popup-icon');
const inlinePopupText = document.getElementById('inline-popup-text');

// Các phần tử Thẻ Sinh Viên HUTECH
const studentCard = document.getElementById('student-card');
const cardAvatar = document.getElementById('card-avatar');
const cardFullName = document.getElementById('card-fullname');
const cardMssv = document.getElementById('card-mssv');
const cardDob = document.getElementById('card-dob');
const cardYear = document.getElementById('card-year');
const rowYear = document.getElementById('row-year');
const cardSecurityStatus = document.getElementById('card-security-status');

const btnScanCard = document.getElementById('btn-scan-card');
const btnUnlinkCard = document.getElementById('btn-unlink-card');
const cardFileInput = document.getElementById('card-file-input');
const outputLog = document.getElementById('outputLog');

let currentLoggedInUser = '';
let popupTimer = null;

/**
 * Hiển thị bảng Pop-up nhỏ ngay dưới 2 nút bấm
 */
export function showInlinePopup(type, icon, text, autoHideMs = 3000) {
    if (!inlinePopup) return;

    if (popupTimer) clearTimeout(popupTimer);

    inlinePopup.classList.remove('hidden', 'popup-success', 'popup-error', 'popup-info');
    void inlinePopup.offsetWidth; // Kích hoạt reflow animation

    inlinePopup.classList.add(`popup-${type}`);
    if (inlinePopupIcon) inlinePopupIcon.innerText = icon;
    if (inlinePopupText) inlinePopupText.innerText = text;

    if (autoHideMs > 0) {
        popupTimer = setTimeout(() => {
            inlinePopup.classList.add('hidden');
        }, autoHideMs);
    }
}

/**
 * Ghi log vào Live Security Inspector và đồng bộ thông báo Pop-up
 */
export function logToInspector(message, isReset = false) {
    if (outputLog) {
        if (isReset) {
            outputLog.innerText = message + '\n';
        } else {
            outputLog.innerText += message + '\n';
        }
        outputLog.scrollTop = outputLog.scrollHeight;
    }

    // Nếu đang ở màn hình đăng nhập, cập nhật pop-up nhỏ
    if (guestView && !guestView.classList.contains('hidden')) {
        const cleanText = message.replace(/^[❌✅🎉🔓🟡🟢🔵⚠️]+\s*/, '');
        if (message.includes('❌')) {
            showInlinePopup('error', '❌', cleanText, 4000);
        } else if (message.includes('✅') || message.includes('🎉') || message.includes('🔓')) {
            showInlinePopup('success', '✅', cleanText, 2500);
        } else {
            showInlinePopup('info', '⏳', cleanText, 0);
        }
    }
}

function setButtonsLoading(isLoading) {
    if (btnRegister) btnRegister.disabled = isLoading;
    if (btnLogin) btnLogin.disabled = isLoading;
}

/**
 * Chuyển đổi qua lại giữa màn hình Khách và Dashboard
 */
function switchView(isLoggedIn, username = '') {
    if (isLoggedIn) {
        currentLoggedInUser = username;
        if (welcomeMessage) welcomeMessage.innerText = `👋 Xin chào, ${username}!`;
        guestView.classList.add('hidden');
        dashboardView.classList.remove('hidden');
        loadUserProfile();
    } else {
        currentLoggedInUser = '';
        dashboardView.classList.add('hidden');
        guestView.classList.remove('hidden');
        if (inputUsername) inputUsername.value = '';
        if (inlinePopup) inlinePopup.classList.add('hidden');
    }
}

/**
 * Tải dữ liệu hồ sơ sinh viên từ Backend và hiển thị lên Thẻ
 */
async function loadUserProfile() {
    try {
        const res = await fetch('/api/user/profile');
        if (!res.ok) return;
        const data = await res.json();
        const profile = data.profile || {};

        const cardUserEl = document.getElementById('card-username');
        if (cardUserEl) cardUserEl.innerText = `@${data.username || currentLoggedInUser}`;

        if (cardFullName) cardFullName.innerText = profile.fullName || data.username;
        if (cardMssv) cardMssv.innerText = profile.studentId || '(Chưa liên kết)';
        if (cardDob) cardDob.innerText = profile.dob || '--/--/----';
        if (cardAvatar && profile.avatar) cardAvatar.src = profile.avatar;

        if (profile.isVerifiedCard) {
            if (studentCard) {
                studentCard.classList.remove('unverified');
                studentCard.classList.add('verified');
            }
            if (btnScanCard) btnScanCard.innerText = '📷 Quét lại thẻ để cập nhật thông tin';
            if (btnUnlinkCard) btnUnlinkCard.style.display = 'block';

            if (rowYear) {
                rowYear.style.display = 'flex';
                if (cardYear) cardYear.innerText = profile.academicYear || '';
            }

            if (cardSecurityStatus) {
                cardSecurityStatus.innerText = 'Đã xác thực';
                cardSecurityStatus.style.color = 'var(--success)';
            }
        } else {
            if (studentCard) {
                studentCard.classList.remove('verified');
                studentCard.classList.add('unverified');
            }
            if (btnScanCard) btnScanCard.innerText = '📷 Quét Thẻ Sinh Viên';
            if (btnUnlinkCard) btnUnlinkCard.style.display = 'none';

            if (rowYear) {
                rowYear.style.display = 'none';
            }

            if (cardSecurityStatus) {
                cardSecurityStatus.innerText = 'Chưa xác thực';
                cardSecurityStatus.style.color = 'var(--text-muted)';
            }
        }
    } catch (err) {
        console.error("Lỗi khi tải hồ sơ sinh viên:", err);
    }
}

// ==========================================
// 1. SỰ KIỆN NÚT "SIGN UP" (ĐĂNG KÝ PASSKEY)
// ==========================================
if (btnRegister) {
    btnRegister.addEventListener('click', async () => {
        const username = inputUsername ? inputUsername.value.trim() : '';
        const hoTen = inputHoTen ? inputHoTen.value.trim() : '';
        const ngaySinh = inputNgaySinh ? inputNgaySinh.value.trim() : '';

        if (!username) {
            showInlinePopup('error', '⚠️', 'Vui lòng nhập Username (MSSV)!', 3000);
            if (inputUsername) inputUsername.focus();
            return;
        }

        setButtonsLoading(true);
        try {
            const result = await handleRegister(username, hoTen, ngaySinh, logToInspector);

            if (result && result.success) {
                btnRegister.classList.add('btn-success-pop');
                showInlinePopup('success', '🎉', 'Đã đăng ký thành công! Hãy bấm Login.', 3000);

                setTimeout(() => {
                    btnRegister.classList.remove('btn-success-pop');
                }, 1500);
            }
        } catch (error) {
            showInlinePopup('error', '❌', `Lỗi: ${error.message}`, 4000);
        } finally {
            setButtonsLoading(false);
        }
    });
}

// ==========================================
// 2. SỰ KIỆN NÚT "LOGIN" (ĐĂNG NHẬP PASSKEY)
// ==========================================
if (btnLogin) {
    btnLogin.addEventListener('click', async () => {
        const username = inputUsername ? inputUsername.value.trim() : '';
        if (!username) {
            showInlinePopup('error', '⚠️', 'Vui lòng nhập Username (MSSV)!', 3000);
            if (inputUsername) inputUsername.focus();
            return;
        }

        setButtonsLoading(true);
        try {
            const result = await handleLogin(username, logToInspector);
            if (result && result.success) {
                btnLogin.classList.add('btn-success-pop');
                showInlinePopup('success', '✅', 'Đăng nhập thành công!', 2000);

                setTimeout(() => {
                    btnLogin.classList.remove('btn-success-pop');
                    switchView(true, username);
                }, 1200);
            }
        } catch (error) {
            showInlinePopup('error', '❌', `Lỗi: ${error.message}`, 4000);
        } finally {
            setButtonsLoading(false);
        }
    });
}

// ==========================================
// 3. SỰ KIỆN NÚT "LOGOUT" (ĐĂNG XUẤT)
// ==========================================
if (btnLogout) {
    btnLogout.addEventListener('click', async () => {
        logToInspector(`[Đăng xuất] Đã đăng xuất tài khoản: ${currentLoggedInUser}`, true);
        try {
            await handleLogout(logToInspector);
        } catch (e) {
            // Bỏ qua lỗi
        }
        switchView(false);
    });
}

// ==========================================
// 4. SỰ KIỆN: QUÉT THẺ SINH VIÊN KÉP (DUAL-SCAN)
// ==========================================
if (btnScanCard && cardFileInput) {
    btnScanCard.addEventListener('click', () => {
        cardFileInput.click();
    });

    cardFileInput.addEventListener('change', async (event) => {
        const file = event.target.files && event.target.files[0];
        if (!file) return;

        logToInspector(`[DUAL-SCAN] Bắt đầu phân tích hình ảnh thẻ: ${file.name}...`, true);
        btnScanCard.disabled = true;
        const oldText = btnScanCard.innerText;
        btnScanCard.innerText = "⏳ Đang quét thẻ sinh viên...";

        try {
            const scanResult = await scanStudentCardDual(file, logToInspector);

            if (!scanResult || !scanResult.studentId) {
                throw new Error("Không thể bóc tách MSSV từ hình ảnh thẻ!");
            }

            logToInspector(`[KẾT QUẢ DUAL-SCAN] MSSV: ${scanResult.studentId} | Họ tên: ${scanResult.fullName || 'N/A'}`);
            logToInspector("🟡 Đang gửi thông tin thẻ lên máy chủ để liên kết và xác minh danh tính...");

            const response = await fetch('/api/user/profile/verify-card', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(scanResult)
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Không thể xác thực thẻ với hệ thống!");
            }

            logToInspector("✅ [XÁC THỰC THÀNH CÔNG] Đã liên kết Thẻ Sinh Viên HUTECH với tài khoản!");
            if (data.revokedFakeAccount) {
                logToInspector(`🚨 [BẢO MẬT] Đã thu hồi tài khoản mạo danh trước đó: ${data.revokedFakeAccount}`);
            }

            await loadUserProfile();
            alert(`Xác thực thẻ thành công!\nMSSV: ${scanResult.studentId}\nHọ tên: ${scanResult.fullName || ''}`);

        } catch (error) {
            logToInspector(`❌ [LỖI QUÉT THẺ]: ${error.message}`);
            alert(`Lỗi quét thẻ: ${error.message}`);
        } finally {
            btnScanCard.disabled = false;
            btnScanCard.innerText = oldText;
            cardFileInput.value = '';
        }
    });
}

// ==========================================
// 5. SỰ KIỆN: HỦY LIÊN KẾT THẺ (STEP-UP AUTH BẰNG PASSKEY)
// ==========================================
if (btnUnlinkCard) {
    btnUnlinkCard.addEventListener('click', async () => {
        const confirmUnlink = confirm("Thao tác hủy liên kết thẻ sinh viên yêu cầu xác thực.\n\nBạn có muốn tiếp tục xác thực không?");
        if (!confirmUnlink) return;

        btnUnlinkCard.disabled = true;
        const originalText = btnUnlinkCard.innerText;
        btnUnlinkCard.innerText = "⏳ Đang xác thực sinh trắc học...";

        logToInspector("🔐 [STEP-UP AUTH] Bắt đầu quy trình xác thực sinh trắc học để hủy liên kết thẻ...", true);

        try {
            const result = await handleStepUpUnlinkCard(logToInspector);
            if (result.success) {
                logToInspector("🎉 [HOÀN TẤT] Xác thực thành công! Đã hủy liên kết thẻ sinh viên.");
                await loadUserProfile();
                alert("Đã hủy liên kết thẻ.");
            } else {
                throw new Error(result.error || "Xác thực danh tính thất bại. Thẻ sinh viên vẫn được giữ nguyên!");
            }
        } catch (err) {
            logToInspector(`${err.message}`);
            alert(`${err.message}`);
        } finally {
            btnUnlinkCard.disabled = false;
            btnUnlinkCard.innerText = originalText;
        }
    });
}
