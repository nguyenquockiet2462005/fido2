/**
 * public/js/ui.js - TRÌNH ĐIỀU KHIỂN GIAO DIỆN & LIVE INSPECTOR
 */

import { handleRegister, handleLogin, handleLogout } from './webauthn.js';

// Các phần tử Giao diện
const outputLog = document.getElementById('outputLog');
const guestView = document.getElementById('guest-view');
const dashboardView = document.getElementById('dashboard-view');

const btnRegister = document.getElementById('btn-register');
const btnLogin = document.getElementById('btn-login');
const btnLogout = document.getElementById('btn-logout');

const inputUsername = document.getElementById('username');
const welcomeMessage = document.getElementById('welcome-message');

let currentLoggedInUser = '';

// Hàm ghi log vào Live Inspector
function logToInspector(message, isReset = false) {
    if (isReset) {
        outputLog.innerText = message + '\n';
    } else {
        outputLog.innerText += message + '\n';
    }
    outputLog.scrollTop = outputLog.scrollHeight;
}

// Hàm chuyển đổi giữa Guest View và Dashboard View
function switchView(isLoggedIn, username = '') {
    if (isLoggedIn) {
        currentLoggedInUser = username;
        welcomeMessage.innerText = `👋 Xin chào, ${username}!`;
        guestView.classList.add('hidden');
        dashboardView.classList.remove('hidden');
    } else {
        currentLoggedInUser = '';
        dashboardView.classList.add('hidden');
        guestView.classList.remove('hidden');
    }
}

// ==========================================
// BẮT SỰ KIỆN NÚT BẤM
// ==========================================

// 1. Nút Đăng ký Passkey
btnRegister.addEventListener('click', async () => {
    const username = inputUsername.value.trim();
    if (!username) return alert("Vui lòng nhập tên người dùng!");

    logToInspector(`[Đăng ký] Bắt đầu tạo Passkey cho tài khoản: ${username}`, true);
    const result = await handleRegister(username, logToInspector);

    if (result && result.success) {
        alert("Đăng ký Passkey thành công! Bây giờ bạn có thể bấm Đăng nhập.");
    }
});

// 2. Nút Đăng nhập Passkey
btnLogin.addEventListener('click', async () => {
    const username = inputUsername.value.trim();
    if (!username) return alert("Vui lòng nhập tên người dùng!");

    logToInspector(`[Đăng nhập] Bắt đầu xác thực cho tài khoản: ${username}`, true);
    const result = await handleLogin(username, logToInspector);

    if (result && result.success) {
        switchView(true, username);
    }
});

// 3. Nút Đăng xuất khỏi tài khoản (Quay về màn hình Trang khách lập tức)
btnLogout.addEventListener('click', async () => {
    logToInspector(`[Đăng xuất] Đã đăng xuất tài khoản: ${currentLoggedInUser}`, true);
    
    // Gọi hàm logout an toàn (nếu backend hỗ trợ)
    try {
        await handleLogout(logToInspector);
    } catch (e) {
        // Bỏ qua lỗi backend nếu không có API
    }

    // Ép chuyển ngay lập tức về giao diện Guest ban đầu
    switchView(false);
});