/**
 * public/js/ui.js - Điều khiển trang Login/Register (index.html)
 * Sau khi đăng nhập -> điều hướng theo role:
 *   admin   -> dashboard.html
 *   student -> workspace.html
 */

import { handleRegister, handleLogin } from './webauthn.js';

// ==========================================
// DOM ELEMENTS
// ==========================================
const btnRegister   = document.getElementById('btn-register');
const btnLogin      = document.getElementById('btn-login');
const inputUsername = document.getElementById('username');
const inlinePopup   = document.getElementById('inline-popup');
const inlinePopupText = document.getElementById('inline-popup-text');

let popupTimer = null;

// ==========================================
// HÀM TIỆN ÍCH: HIỂN THỊ POP-UP THÔNG BÁO
// ==========================================
function showInlinePopup(type, text, autoHideMs = 3000) {
    if (!inlinePopup) return;
    if (popupTimer) clearTimeout(popupTimer);

    inlinePopup.classList.remove('hidden', 'popup-success', 'popup-error', 'popup-info');
    void inlinePopup.offsetWidth;
    inlinePopup.classList.add(`popup-${type}`);
    if (inlinePopupText) inlinePopupText.innerText = text;

    if (autoHideMs > 0) {
        popupTimer = setTimeout(() => inlinePopup.classList.add('hidden'), autoHideMs);
    }
}

// ==========================================
// HÀM TIỆN ÍCH: LOG INSPECTOR (dùng bởi webauthn.js)
// ==========================================
export function logToInspector(message) {
    const cleanText = message.replace(/^[❌✅🎉🔓🟡🟢🔵⚠️🔴]+\s*/, '');
    if (message.includes('❌')) {
        showInlinePopup('error', cleanText, 4000);
    } else if (message.includes('✅') || message.includes('🎉') || message.includes('🔓')) {
        showInlinePopup('success', cleanText, 2500);
    } else {
        showInlinePopup('info', cleanText, 0);
    }
}

// ==========================================
// HÀM PHÂN QUYỀN ĐIỀU HƯỚNG
// ==========================================
function redirectByRole(role) {
    if (role === 'admin') {
        window.location.href = 'dashboard.html';
    } else {
        window.location.href = 'workspace.html';
    }
}

function setButtonsLoading(isLoading) {
    if (btnRegister) btnRegister.disabled = isLoading;
    if (btnLogin)    btnLogin.disabled    = isLoading;
}

// ==========================================
// 1. KIỂM TRA SESSION KHI MỞ TRANG
// Nếu đã đăng nhập -> redirect luôn, không ở lại trang login
// ==========================================
async function checkCurrentSession() {
    try {
        const res = await fetch('/api/user/profile');
        if (res.ok) {
            const data = await res.json();
            if (data && data.username) {
                redirectByRole(data.role);
            }
        }
    } catch (e) {
        // Chưa đăng nhập -> giữ nguyên trang login
    }
}
checkCurrentSession();

// ==========================================
// 2. NÚT ĐĂNG KÝ (REGISTER)
// ==========================================
if (btnRegister) {
    btnRegister.addEventListener('click', async () => {
        const username = inputUsername ? inputUsername.value.trim() : '';
        if (!username) {
            showInlinePopup('error', 'Vui lòng nhập Username!', 3000);
            if (inputUsername) inputUsername.focus();
            return;
        }

        setButtonsLoading(true);
        try {
            const result = await handleRegister(username, '', '', logToInspector);
            if (result && result.success) {
                btnRegister.classList.add('btn-success-pop');
                showInlinePopup('success', 'Đăng ký thành công! Hãy bấm Đăng Nhập.', 3500);
                setTimeout(() => btnRegister.classList.remove('btn-success-pop'), 1500);
            }
        } catch (error) {
            let msg = error.message;
            if (msg.includes('timed out') || msg.includes('not allowed')) {
                msg = 'Không thể mở xác thực sinh trắc học, vui lòng thử lại!';
            }
            showInlinePopup('error', msg, 4000);
        } finally {
            setButtonsLoading(false);
        }
    });
}

// ==========================================
// 3. NÚT ĐĂNG NHẬP (LOGIN)
// ==========================================
if (btnLogin) {
    btnLogin.addEventListener('click', async () => {
        const username = inputUsername ? inputUsername.value.trim() : '';
        if (!username) {
            showInlinePopup('error', 'Vui lòng nhập Username!', 3000);
            if (inputUsername) inputUsername.focus();
            return;
        }

        setButtonsLoading(true);
        try {
            const result = await handleLogin(username, logToInspector);
            if (result && result.success) {
                btnLogin.classList.add('btn-success-pop');
                showInlinePopup('success', 'Đăng nhập thành công! Đang chuyển hướng...', 2000);

                setTimeout(() => {
                    btnLogin.classList.remove('btn-success-pop');
                    // 🛡️ PHÂN QUYỀN: Admin -> Dashboard | Sinh viên -> Workspace
                    const role = result.user?.role || 'student';
                    redirectByRole(role);
                }, 1200);
            }
        } catch (error) {
            let msg = error.message;
            if (msg.includes('timed out') || msg.includes('not allowed')) {
                msg = 'Không thể mở xác thực sinh trắc học, vui lòng thử lại!';
            }
            showInlinePopup('error', msg, 4000);
        } finally {
            setButtonsLoading(false);
        }
    });
}
