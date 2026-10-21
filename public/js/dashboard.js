/**
 * public/js/dashboard.js - Logic Admin Dashboard với bảo vệ quyền và biểu đồ Chart.js
 */

let allUsersData = [];
let lineChartInstance = null;
let doughnutChartInstance = null;

// Khởi chạy khi vừa tải trang
document.addEventListener('DOMContentLoaded', async () => {
    const ok = await verifyAdminAccess();
    if (ok) {
        fetchUsers();
        renderCharts();
        updateCurrentDate();
    }
});

// 🛡️ Kiểm tra bảo mật: Chỉ Admin mới vào được trang này
async function verifyAdminAccess() {
    try {
        const res = await fetch('/api/user/profile');
        if (!res.ok) {
            alert('⚠️ Vui lòng đăng nhập tài khoản Admin để truy cập!');
            window.location.href = 'index.html';
            return false;
        }
        const data = await res.json();

        // Hiển thị tên admin
        const adminEl = document.getElementById('admin-username');
        if (adminEl) adminEl.innerText = data.username;

        // Cập nhật avatar theo username
        const avatarEl = document.getElementById('admin-avatar');
        if (avatarEl && data.profile?.avatar) avatarEl.src = data.profile.avatar;

        if (data.role !== 'admin') {
            alert('⛔ Bạn không có quyền truy cập vào trang Quản trị này!');
            window.location.href = 'index.html';
            return false;
        }
        return true;
    } catch (err) {
        window.location.href = 'index.html';
        return false;
    }
}

// Gọi API lấy danh sách người dùng (chỉ admin mới nhận được)
async function fetchUsers() {
    try {
        const response = await fetch('/api/users');

        if (response.status === 401 || response.status === 403) {
            alert('⚠️ Khu vực quản trị hạn chế! Vui lòng xác thực FIDO2 với tài khoản Admin.');
            window.location.href = 'index.html';
            return;
        }

        allUsersData = await response.json();

        updateDashboardMetrics(allUsersData);
        renderUserTable(allUsersData);
        renderRecentActivities(allUsersData);

    } catch (error) {
        console.error('Lỗi khi kéo dữ liệu Dashboard:', error);
    }
}

// Cập nhật 4 thẻ thống kê đầu trang
function updateDashboardMetrics(users) {
    let totalKeys = 0;
    let totalCounters = 0;
    let verifiedCards = 0;

    users.forEach(user => {
        const creds = user.credentials || [];
        totalKeys += creds.length;
        creds.forEach(c => { totalCounters += (c.counter || 0); });
        if (user.profile?.isVerifiedCard) verifiedCards++;
    });

    const el = id => document.getElementById(id);
    if (el('stat-total-users')) el('stat-total-users').innerText = users.length;
    if (el('stat-total-keys')) el('stat-total-keys').innerText = totalKeys;
    if (el('stat-verified-cards')) el('stat-verified-cards').innerText = verifiedCards;
    if (el('stat-total-counters')) el('stat-total-counters').innerText = totalCounters;
}

// Hàm tiện ích: Khử mã HTML độc hại (Phòng chống Stored XSS)
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// Vẽ bảng danh sách người dùng
function renderUserTable(users) {
    const tbody = document.getElementById('user-table-body');
    if (!tbody) return;

    if (!users || users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center" style="padding: 24px; color: #9ca3af;">Chưa có tài khoản nào trong hệ thống.</td></tr>`;
        return;
    }

    let rowsHtml = '';
    users.forEach(user => {
        const creds = user.credentials || [];
        const passkeyCount = creds.length;
        const latestCounter = creds.length > 0 ? (creds[0].counter || 0) : 0;
        const hoTen = user.hoTen || user.profile?.fullName || user.username;
        const ngaySinh = user.ngaySinh || user.profile?.dob || '--/--/----';

        const safeUsername = escapeHtml(user.username);
        const safeHoTen = escapeHtml(hoTen);
        const safeNgaySinh = escapeHtml(ngaySinh);
        const safeCounter = escapeHtml(latestCounter);

        const statusTag = passkeyCount > 0
            ? `<span class="status-tag tag-open">Active</span>`
            : `<span class="status-tag tag-process">Pending</span>`;

        const roleTag = user.role === 'admin'
            ? `<span class="role-tag role-admin">Admin</span>`
            : `<span class="role-tag role-student">Sinh viên</span>`;

        rowsHtml += `
            <tr>
                <td><strong style="color: #4338ca;">${safeUsername}</strong> ${roleTag}</td>
                <td>${safeHoTen}</td>
                <td style="color: #6b7280;">${safeNgaySinh}</td>
                <td><strong>${passkeyCount}</strong></td>
                <td><span style="font-family: monospace; color: #10b981; font-weight: 700;">${safeCounter}</span></td>
                <td>${statusTag}</td>
            </tr>
        `;
    });

    tbody.innerHTML = rowsHtml;

    const showEl = document.getElementById('table-showing-text');
    if (showEl) showEl.innerText = `Hiển thị ${users.length} tài khoản đã đăng ký`;
}

// Lọc bảng theo từ khóa
function filterUserTable() {
    const query = document.getElementById('user-search-input').value.toLowerCase();
    const filtered = allUsersData.filter(user => {
        const name = (user.hoTen || user.profile?.fullName || '').toLowerCase();
        return user.username.toLowerCase().includes(query) || name.includes(query);
    });
    renderUserTable(filtered);
}
window.filterUserTable = filterUserTable;

// Hiển thị hoạt động gần đây
function renderRecentActivities(users) {
    const activityList = document.getElementById('activity-list');
    if (!activityList) return;

    const recent = users.filter(u => (u.credentials || []).length > 0).slice(0, 5);

    if (recent.length === 0) {
        activityList.innerHTML = `<p style="color: #9ca3af; font-size: 0.8rem;">Chưa ghi nhận hoạt động nào.</p>`;
        return;
    }

    const badgeColors = ['badge-red', 'badge-purple', 'badge-blue'];
    let actHtml = '';
    recent.forEach((user, idx) => {
        const badgeClass = badgeColors[idx % badgeColors.length];
        const timeAgo = `${(idx + 1) * 8} phút trước`;
        const safeUser = escapeHtml(user.username);
        actHtml += `
            <div class="activity-item">
                <div class="activity-time">${timeAgo}</div>
                <div class="activity-badge ${badgeClass}">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
                </div>
                <div class="activity-info">
                    <h4>Xác thực Passkey thành công</h4>
                    <p>${safeUser} vừa đăng nhập bằng sinh trắc học</p>
                </div>
            </div>
        `;
    });
    activityList.innerHTML = actHtml;
}

// Khởi tạo biểu đồ Chart.js
function renderCharts() {
    const ctxLine = document.getElementById('lineChart');
    const ctxDoughnut = document.getElementById('doughnutChart');
    if (!ctxLine || !ctxDoughnut) return;

    // Gradient tím mận
    const ctxL = ctxLine.getContext('2d');
    const gradPurple = ctxL.createLinearGradient(0, 0, 0, 180);
    gradPurple.addColorStop(0, 'rgba(99, 102, 241, 0.45)');
    gradPurple.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

    const gradOrange = ctxL.createLinearGradient(0, 0, 0, 180);
    gradOrange.addColorStop(0, 'rgba(249, 115, 22, 0.35)');
    gradOrange.addColorStop(1, 'rgba(249, 115, 22, 0.0)');

    if (lineChartInstance) lineChartInstance.destroy();
    lineChartInstance = new Chart(ctxL, {
        type: 'line',
        data: {
            labels: ['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'T8', 'T9', 'T10'],
            datasets: [
                {
                    label: 'Xác thực Online',
                    data: [8, 14, 12, 20, 18, 25, 22, 30, 28, 35],
                    borderColor: '#6366f1',
                    backgroundColor: gradPurple,
                    fill: true, tension: 0.4, borderWidth: 2.5,
                    pointRadius: 3, pointBackgroundColor: '#6366f1'
                },
                {
                    label: 'Đăng ký Passkey mới',
                    data: [4, 8, 10, 12, 15, 14, 18, 20, 22, 24],
                    borderColor: '#f97316',
                    backgroundColor: gradOrange,
                    fill: true, tension: 0.4, borderWidth: 2,
                    pointRadius: 3, pointBackgroundColor: '#f97316'
                }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { display: false } },
                y: { grid: { color: '#f3f4f6' }, beginAtZero: true }
            }
        }
    });

    if (doughnutChartInstance) doughnutChartInstance.destroy();
    doughnutChartInstance = new Chart(ctxDoughnut.getContext('2d'), {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [70, 20, 10],
                backgroundColor: ['#6366f1', '#fbbf24', '#f97316'],
                borderWidth: 0, borderRadius: 8
            }]
        },
        options: {
            cutout: '76%', responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { enabled: true } }
        }
    });
}

// Hiển thị ngày hiện tại
function updateCurrentDate() {
    const el = document.getElementById('current-date-filter');
    if (el) {
        const now = new Date();
        el.innerText = now.toLocaleDateString('vi-VN');
    }
}

// Đăng xuất admin
async function logoutAdmin() {
    await fetch('/api/auth/logout', { method: 'POST' });
    window.location.href = 'index.html';
}

// Gắn fetchUsers vào window để nút onclick gọi được
window.fetchUsers = fetchUsers;
window.logoutAdmin = logoutAdmin;
