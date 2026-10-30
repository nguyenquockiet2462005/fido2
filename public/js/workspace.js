/**
 * public/js/workspace.js - Điều khiển giao diện Student Workspace (workspace.html)
 */

import { handleStepUpUpdateProfile, handleLogout } from './webauthn.js';

const LOGIN_PAGE = 'index.html';
const ADMIN_PAGE = 'dashboard.html';

const btnLogout = document.getElementById('btn-logout');
const btnOpenEdit = document.getElementById('btn-open-edit');
const modalEdit = document.getElementById('modal-edit-profile');
const btnCloseEdit = document.getElementById('btn-close-edit');
const btnCancelEdit = document.getElementById('btn-cancel-edit');
const btnSaveStepUp = document.getElementById('btn-save-stepup');
const scanProgress = document.getElementById('ws-scan-progress');

const editFullname = document.getElementById('edit-fullname');
const editMssv = document.getElementById('edit-mssv');
const editDob = document.getElementById('edit-dob');
const editFaculty = document.getElementById('edit-faculty');
const editYear = document.getElementById('edit-year');

let currentUser = null;
let progressTimer = null;

// Helper gán text an toàn, nhanh và chống lỗi null DOM
function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function showProgress(msg, isError = false) {
    if (!scanProgress) return;
    if (progressTimer) clearTimeout(progressTimer);

    scanProgress.classList.remove('hidden');
    scanProgress.classList.toggle('error', isError);
    scanProgress.textContent = msg;
}

function hideProgress(delay = 4000) {
    if (!scanProgress) return;
    if (progressTimer) clearTimeout(progressTimer);

    progressTimer = setTimeout(() => {
        scanProgress.classList.add('hidden');
    }, delay);
}

// Chuyển đổi 'dd/mm/yyyy' hoặc 'yyyy-mm-dd' sang 'yyyy-mm-dd' cho <input type="date">
function toDateInputValue(dobStr) {
    if (!dobStr || typeof dobStr !== 'string') return '';
    const trimmed = dobStr.trim();
    if (trimmed.includes('/')) {
        const parts = trimmed.split('/');
        if (parts.length === 3) {
            const day = parts[0].padStart(2, '0');
            const month = parts[1].padStart(2, '0');
            const year = parts[2];
            return `${year}-${month}-${day}`;
        }
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
        return trimmed;
    }
    return '';
}

// Chuyển đổi 'yyyy-mm-dd' từ <input type="date"> sang 'dd/mm/yyyy' hiển thị chuẩn VN
function fromDateInputValue(ymdStr) {
    if (!ymdStr || typeof ymdStr !== 'string') return '';
    const trimmed = ymdStr.trim();
    if (trimmed.includes('-')) {
        const parts = trimmed.split('-');
        if (parts.length === 3) {
            const [year, month, day] = parts;
            return `${day.padStart(2, '0')}/${month.padStart(2, '0')}/${year}`;
        }
    }
    return trimmed;
}

function openModal() {
    if (!modalEdit) return;
    if (currentUser) {
        if (editFullname) editFullname.value = currentUser.profile?.fullName || currentUser.hoTen || '';
        if (editMssv) editMssv.value = currentUser.profile?.studentId || '(Chưa cấp)';
        if (editDob) editDob.value = toDateInputValue(currentUser.profile?.dob || currentUser.ngaySinh || '');
        if (editFaculty) editFaculty.value = currentUser.profile?.faculty || '';
        if (editYear) editYear.value = currentUser.profile?.academicYear || '';
    }
    modalEdit.classList.add('active');
    if (editFullname) editFullname.focus();
}

function closeModal() {
    if (modalEdit) modalEdit.classList.remove('active');
}

// Tách riêng hàm render giao diện để dễ debug và không gây lỗi chuyển hướng nhầm
function renderProfile(u) {
    const displayName = u.profile?.fullName || u.hoTen || u.username || '';
    const shortName = displayName.split(' ').slice(-2).join(' ');

    setText('ws-fullname', displayName);
    setText('ws-shortname', shortName || displayName);
    setText('ws-username', u.username);
    setText('val-name', displayName);
    setText('val-mssv', u.profile?.studentId || '(Chưa cấp)');
    setText('val-dob', u.profile?.dob || u.ngaySinh || '--/--/----');
    setText('val-creds-count', `${u.credentialsCount || 0} khóa Passkey`);

    const safeSeed = encodeURIComponent(u.username || 'user');
    const avatarUrl = u.profile?.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${safeSeed}`;
    const wsAvatar = document.getElementById('ws-avatar');
    const wsProfileAvatar = document.getElementById('ws-profile-avatar');
    if (wsAvatar) wsAvatar.src = avatarUrl;
    if (wsProfileAvatar) wsProfileAvatar.src = avatarUrl;

    const rowFaculty = document.getElementById('row-faculty');
    if (rowFaculty) {
        if (u.profile?.faculty) {
            setText('val-faculty', u.profile.faculty);
            rowFaculty.classList.remove('hidden');
        } else {
            rowFaculty.classList.add('hidden');
        }
    }

    const rowYear = document.getElementById('row-year');
    if (rowYear) {
        if (u.profile?.academicYear) {
            setText('val-year', u.profile.academicYear);
            rowYear.classList.remove('hidden');
        } else {
            rowYear.classList.add('hidden');
        }
    }
}

// Tải dữ liệu hồ sơ từ backend (Chỉ redirect khi 401/403/404 để chống lặp vô hạn)
async function loadData() {
    let res;
    try {
        res = await fetch('/api/user/me');
    } catch (networkErr) {
        console.error('Lỗi kết nối khi tải hồ sơ:', networkErr);
        showProgress('❌ Không thể kết nối máy chủ. Vui lòng kiểm tra mạng!', true);
        return;
    }

    if (res.status === 401 || res.status === 403 || res.status === 404) {
        window.location.href = LOGIN_PAGE;
        return;
    }

    if (!res.ok) {
        showProgress(`❌ Lỗi tải dữ liệu hồ sơ (${res.status}). Vui lòng tải lại trang!`, true);
        return;
    }

    try {
        const u = await res.json();
        currentUser = u;

        if (u.role === 'admin') {
            window.location.href = ADMIN_PAGE;
            return;
        }

        renderProfile(u);
    } catch (err) {
        console.error('Lỗi hiển thị dữ liệu hồ sơ:', err);
        showProgress('❌ Đã xảy ra lỗi khi hiển thị thông tin hồ sơ.', true);
    }
}

// Sự kiện đóng/mở Modal
if (btnOpenEdit) btnOpenEdit.addEventListener('click', openModal);
if (btnCloseEdit) btnCloseEdit.addEventListener('click', closeModal);
if (btnCancelEdit) btnCancelEdit.addEventListener('click', closeModal);

if (modalEdit) {
    modalEdit.addEventListener('click', (e) => {
        if (e.target === modalEdit) closeModal();
    });
}

window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modalEdit?.classList.contains('active')) {
        closeModal();
    }
});

// Sự kiện: Bấm Lưu Thay Đổi -> Kích hoạt FIDO2 Step-Up Authentication
if (btnSaveStepUp) {
    btnSaveStepUp.addEventListener('click', async () => {
        const profileData = {
            fullName: editFullname ? editFullname.value.trim() : '',
            dob: fromDateInputValue(editDob ? editDob.value : ''),
            faculty: editFaculty ? editFaculty.value.trim() : '',
            academicYear: editYear ? editYear.value.trim() : '',
        };

        if (!profileData.fullName) {
            if (editFullname) editFullname.focus();
            showProgress('❌ Vui lòng nhập Họ và Tên sinh viên!', true);
            hideProgress(3500);
            return;
        }

        btnSaveStepUp.disabled = true;
        const origHtml = btnSaveStepUp.innerHTML;
        btnSaveStepUp.textContent = 'Đang chờ quét vân tay...';
        closeModal();
        showProgress('Đang mở cảm biến...');

        try {
            const result = await handleStepUpUpdateProfile(profileData, (msg) => showProgress(msg));
            if (result && result.success) {
                showProgress('✅ Cập nhật thành công!');
                hideProgress(3000);
                await loadData();
            } else {
                const errMsg = result?.error || 'Xác thực thất bại.';
                const isCancel = Boolean(result?.cancelled);
                showProgress(isCancel ? 'ℹ️ ' + errMsg : '❌ ' + errMsg, !isCancel);
                hideProgress(4000);
            }
        } catch (err) {
            showProgress('❌ ' + err.message, true);
            hideProgress(4000);
        } finally {
            btnSaveStepUp.disabled = false;
            btnSaveStepUp.innerHTML = origHtml;
        }
    });
}

// Sự kiện: Đăng xuất
if (btnLogout) {
    btnLogout.addEventListener('click', async () => {
        await handleLogout();
        window.location.href = LOGIN_PAGE;
    });
}

loadData();