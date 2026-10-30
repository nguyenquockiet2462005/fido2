/**
 * public/js/dashboard.js - Logic Admin Dashboard với bảo vệ quyền và biểu đồ Chart.js
 */
import { handleLogout } from './webauthn.js';

const LOGIN_PAGE = 'index.html';
const WORKSPACE_PAGE = 'workspace.html';

let allUsersData = [];
let lineChartInstance = null;
let doughnutChartInstance = null;

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

// Helper lấy số lượng Passkey của user (tương thích cả DTO rút gọn lẫn mảng credentials)
function getUserPasskeyCount(user) {
  if (typeof user.credentialsCount === 'number') return user.credentialsCount;
  return Array.isArray(user.credentials) ? user.credentials.length : 0;
}

// Helper lấy tổng Sign Counter (ước lượng) của user
function getUserTotalCounter(user) {
  if (typeof user.totalCounter === 'number') return user.totalCounter;
  if (!Array.isArray(user.credentials)) return 0;
  return user.credentials.reduce((sum, c) => sum + (c.counter || 0), 0);
}

// Khởi chạy và gắn sự kiện khi vừa tải trang
document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('btn-logout-admin')?.addEventListener('click', logoutAdmin);
  document.getElementById('btn-refresh-top')?.addEventListener('click', fetchUsers);
  document.getElementById('btn-refresh-table')?.addEventListener('click', fetchUsers);
  document.getElementById('user-search-input')?.addEventListener('input', filterUserTable);

  const ok = await verifyAdminAccess();
  if (ok) {
    updateCurrentDate();
    await fetchUsers();
  }
});

// Kiểm tra bảo mật: Chỉ Admin mới vào được trang này
async function verifyAdminAccess() {
  try {
    const res = await fetch('/api/user/profile');
    if (res.status === 401 || res.status === 403 || res.status === 404) {
      window.location.href = LOGIN_PAGE;
      return false;
    }
    if (!res.ok) {
      renderLoadError(`Không thể xác minh phiên Quản trị viên (HTTP ${res.status}).`);
      return false;
    }

    const data = await res.json();
    if (data.role !== 'admin') {
      window.location.href = WORKSPACE_PAGE;
      return false;
    }

    setText('admin-username', data.username);

    const avatarEl = document.getElementById('admin-avatar');
    if (avatarEl && data.profile?.avatar) {
      avatarEl.src = data.profile.avatar;
    }

    return true;
  } catch (err) {
    console.error('Lỗi kiểm tra quyền Admin:', err);
    renderLoadError('Mất kết nối tới máy chủ khi kiểm tra quyền truy cập.');
    return false;
  }
}

// Hiển thị thông báo lỗi trực quan trên bảng và danh sách hoạt động
function renderLoadError(message) {
  const tbody = document.getElementById('user-table-body');
  if (tbody) {
    tbody.innerHTML = '';
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'text-center empty-table-cell';
    td.textContent = `${message} Bấm Làm mới để thử lại.`;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  const activityList = document.getElementById('activity-list');
  if (activityList) {
    activityList.innerHTML = '';
    const p = document.createElement('p');
    p.className = 'empty-hint';
    p.textContent = message;
    activityList.appendChild(p);
  }
}

// Gọi API lấy danh sách người dùng (chỉ admin mới nhận được)
async function fetchUsers() {
  try {
    const response = await fetch('/api/users');

    if (response.status === 401 || response.status === 403) {
      window.location.href = LOGIN_PAGE;
      return;
    }
    if (!response.ok) {
      renderLoadError(`Không thể tải dữ liệu (HTTP ${response.status}).`);
      return;
    }

    const data = await response.json();
    if (!Array.isArray(data)) {
      renderLoadError('Dữ liệu phản hồi từ máy chủ không hợp lệ.');
      return;
    }

    allUsersData = data;
    updateDashboardMetrics(allUsersData);
    // Giữ nguyên bộ lọc tìm kiếm hiện tại khi bấm Làm mới
    filterUserTable();
    renderRecentActivities(allUsersData);
    renderCharts(allUsersData);
  } catch (error) {
    console.error('Lỗi khi kéo dữ liệu Dashboard:', error);
    renderLoadError('Lỗi kết nối mạng khi tải danh sách người dùng.');
  }
}

// Cập nhật 4 thẻ thống kê đầu trang
function updateDashboardMetrics(users) {
  let totalKeys = 0;
  let totalCounters = 0;
  let verifiedCards = 0;
  let usersWithPasskey = 0;

  users.forEach(user => {
    const keyCount = getUserPasskeyCount(user);
    totalKeys += keyCount;
    if (keyCount > 0) usersWithPasskey++;
    totalCounters += getUserTotalCounter(user);
    if (user.profile?.isVerifiedCard) verifiedCards++;
  });

  const coveragePct = users.length > 0
    ? `${Math.round((usersWithPasskey / users.length) * 100)}%`
    : '0%';

  setText('stat-total-users', users.length);
  setText('stat-total-keys', totalKeys);
  setText('stat-verified-cards', verifiedCards);
  setText('stat-total-counters', totalCounters);
  setText('stat-passkey-coverage', coveragePct);
  setText('doughnut-pct', coveragePct);
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
    tbody.innerHTML = '<tr><td colspan="6" class="text-center empty-table-cell">Không tìm thấy tài khoản nào khớp với điều kiện.</td></tr>';
    setText('table-showing-text', 'Hiển thị 0 tài khoản');
    return;
  }

  let rowsHtml = '';
  users.forEach(user => {
    const passkeyCount = getUserPasskeyCount(user);
    const totalUserCounter = getUserTotalCounter(user);
    const hoTen = user.hoTen || user.profile?.fullName || user.username;
    const ngaySinh = user.ngaySinh || user.profile?.dob || '--/--/----';

    const safeUsername = escapeHtml(user.username);
    const safeHoTen = escapeHtml(hoTen);
    const safeNgaySinh = escapeHtml(ngaySinh);
    const safeCounter = escapeHtml(totalUserCounter);

    const statusTag = passkeyCount > 0
      ? '<span class="status-tag tag-open">Active</span>'
      : '<span class="status-tag tag-process">Pending</span>';

    const roleTag = user.role === 'admin'
      ? '<span class="role-tag role-admin">Admin</span>'
      : '<span class="role-tag role-student">Sinh viên</span>';

    rowsHtml += `
      <tr>
        <td><strong class="cell-username">${safeUsername}</strong> ${roleTag}</td>
        <td>${safeHoTen}</td>
        <td class="cell-dob">${safeNgaySinh}</td>
        <td><strong>${passkeyCount}</strong></td>
        <td><span class="cell-counter">${safeCounter}</span></td>
        <td>${statusTag}</td>
      </tr>
    `;
  });

  tbody.innerHTML = rowsHtml;
  setText('table-showing-text', `Hiển thị ${users.length} / ${allUsersData.length} tài khoản`);
}

// Lọc bảng theo từ khóa
function filterUserTable() {
  const searchEl = document.getElementById('user-search-input');
  const query = searchEl ? searchEl.value.trim().toLowerCase() : '';
  const filtered = allUsersData.filter(user => {
    const name = (user.hoTen || user.profile?.fullName || '').toLowerCase();
    return user.username.toLowerCase().includes(query) || name.includes(query);
  });
  renderUserTable(filtered);
}

// Lấy mốc thời gian số (ms) để sắp xếp hoạt động mới nhất lên đầu
function getActivityTimestamp(user) {
  const raw = user.profile?.updatedAt || user.profile?.verifiedAt || '';
  const ms = Date.parse(raw);
  return Number.isNaN(ms) ? 0 : ms;
}

// Định dạng mốc thời gian thực tế cho danh sách hoạt động
function formatActivityTime(user) {
  const ms = getActivityTimestamp(user);
  if (!ms) return 'Đã kích hoạt';
  return new Date(ms).toLocaleDateString('vi-VN');
}

// Hiển thị hoạt động gần đây (sắp xếp giảm dần theo thời gian thực)
function renderRecentActivities(users) {
  const activityList = document.getElementById('activity-list');
  if (!activityList) return;

  const recent = users
    .filter(u => getUserPasskeyCount(u) > 0)
    .sort((a, b) => getActivityTimestamp(b) - getActivityTimestamp(a))
    .slice(0, 5);

  if (recent.length === 0) {
    activityList.innerHTML = '<p class="empty-hint">Chưa ghi nhận hoạt động nào.</p>';
    return;
  }

  const badgeColors = ['badge-red', 'badge-purple', 'badge-blue'];
  let actHtml = '';
  recent.forEach((user, idx) => {
    const badgeClass = badgeColors[idx % badgeColors.length];
    const timeLabel = escapeHtml(formatActivityTime(user));
    const safeUser = escapeHtml(user.username);
    const hasUpdatedProfile = Boolean(user.profile?.updatedAt);
    const actionTitle = hasUpdatedProfile ? 'Cập nhật hồ sơ Step-Up' : 'Tài khoản Passkey hoạt động';
    const actionDesc = hasUpdatedProfile
      ? `${safeUser} đã xác thực cập nhật hồ sơ`
      : `${safeUser} đã kích hoạt khóa sinh trắc học`;

    actHtml += `
      <div class="activity-item">
        <div class="activity-time">${timeLabel}</div>
        <div class="activity-badge ${badgeClass}">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
        </div>
        <div class="activity-info">
          <h4>${actionTitle}</h4>
          <p>${actionDesc}</p>
        </div>
      </div>
    `;
  });
  activityList.innerHTML = actHtml;
}

// Khởi tạo biểu đồ Chart.js:
// - Biểu đồ tròn (Doughnut): tính toán trực tiếp từ dữ liệu người dùng thực tế trong DB.
// - Biểu đồ đường (Line): dữ liệu minh họa xu hướng theo tháng (do hệ thống không lưu log lịch sử từng lần đăng nhập).
function renderCharts(users = []) {
  if (typeof Chart === 'undefined') return;

  const ctxLine = document.getElementById('lineChart');
  const ctxDoughnut = document.getElementById('doughnutChart');
  if (!ctxLine || !ctxDoughnut) return;

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
          label: 'Xác thực Online (Minh họa)',
          data: [8, 14, 12, 20, 18, 25, 22, 30, 28, 35],
          borderColor: '#6366f1',
          backgroundColor: gradPurple,
          fill: true,
          tension: 0.4,
          borderWidth: 2.5,
          pointRadius: 3,
          pointBackgroundColor: '#6366f1'
        },
        {
          label: 'Đăng ký Passkey mới (Minh họa)',
          data: [4, 8, 10, 12, 15, 14, 18, 20, 22, 24],
          borderColor: '#f97316',
          backgroundColor: gradOrange,
          fill: true,
          tension: 0.4,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#f97316'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: '#f3f4f6' }, beginAtZero: true }
      }
    }
  });

  // Tính toán số liệu thực tế từ DB cho biểu đồ Doughnut
  let verifiedStudents = 0;
  let basicStudents = 0;
  let adminCount = 0;

  users.forEach(u => {
    if (u.role === 'admin') {
      adminCount++;
    } else if (u.profile?.isVerifiedCard) {
      verifiedStudents++;
    } else if (getUserPasskeyCount(u) > 0) {
      basicStudents++;
    }
  });

  const doughnutData = (verifiedStudents + basicStudents + adminCount) > 0
    ? [verifiedStudents, basicStudents, adminCount]
    : [0, 0, 1];

  if (doughnutChartInstance) doughnutChartInstance.destroy();
  doughnutChartInstance = new Chart(ctxDoughnut.getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['SV đã xác thực Step-Up', 'SV có Passkey cơ bản', 'Quản trị viên (Admin)'],
      datasets: [{
        data: doughnutData,
        backgroundColor: ['#6366f1', '#fbbf24', '#f97316'],
        borderWidth: 0,
        borderRadius: 8
      }]
    },
    options: {
      cutout: '76%',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: { enabled: true } }
    }
  });
}

// Hiển thị ngày hiện tại
function updateCurrentDate() {
  const now = new Date();
  setText('current-date-filter', now.toLocaleDateString('vi-VN'));
}

// Đăng xuất admin (tái sử dụng hàm chuẩn từ webauthn.js)
async function logoutAdmin() {
  await handleLogout();
  window.location.href = LOGIN_PAGE;
}
