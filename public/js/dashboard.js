/**
 * public/js/dashboard.js - Logic hiển thị và cập nhật dữ liệu Security Dashboard
 */

// Hàm gọi API lấy danh sách tài khoản và vẽ ra bảng
async function fetchUsers() {
    try {
        const res = await fetch('/api/users-debug');
        const data = await res.json();

        // 1. Cập nhật thẻ tổng số tài khoản
        const totalUsersEl = document.getElementById('stat-total-users');
        if (totalUsersEl) {
            totalUsersEl.innerText = data.totalUsers || 0;
        }

        let totalKeys = 0;
        const tbody = document.getElementById('user-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        // Nếu chưa có tài khoản nào
        if (!data.users || data.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">Chưa có tài khoản nào được tạo.</td></tr>';
            return;
        }

        // 2. Duyệt qua từng tài khoản và tạo dòng trong bảng
        data.users.forEach(user => {
            const credCount = (user.credentials || []).length;
            totalKeys += credCount;

            let transportsBadges = '';
            let counters = [];

            if (credCount === 0) {
                transportsBadges = '<span style="color: #64748b; font-size: 0.85rem;">Chưa có khóa</span>';
            } else {
                user.credentials.forEach(cred => {
                    (cred.transports || []).forEach(t => {
                        if (t === 'internal') transportsBadges += `<span class="badge badge-internal">💻 TouchID/Windows Hello</span>`;
                        else if (t === 'hybrid') transportsBadges += `<span class="badge badge-hybrid">📱 Điện thoại (Hybrid)</span>`;
                        else transportsBadges += `<span class="badge badge-internal">${t}</span>`;
                    });
                    counters.push(`<span class="badge badge-counter">${cred.counter} lần</span>`);
                });
            }

            const row = document.createElement('tr');
            row.innerHTML = `
        <td><strong>👤 ${user.username}</strong></td>
        <td><span class="code-snippet">${user.id}</span></td>
        <td><span style="font-weight: 600; color: ${credCount > 0 ? '#22c55e' : '#94a3b8'};">${credCount} Passkey</span></td>
        <td>${transportsBadges}</td>
        <td>${counters.length > 0 ? counters.join(' ') : '0'}</td>
      `;
            tbody.appendChild(row);
        });

        // 3. Cập nhật thẻ tổng số Passkeys
        const totalKeysEl = document.getElementById('stat-total-keys');
        if (totalKeysEl) {
            totalKeysEl.innerText = totalKeys;
        }

    } catch (err) {
        console.error("Lỗi:", err);
        const tbody = document.getElementById('user-table-body');
        if (tbody) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #ef4444;">Lỗi khi tải dữ liệu: ${err.message}</td></tr>`;
        }
    }
}

// Gắn hàm vào window để nút "Làm mới" (onclick="fetchUsers()") bấm được
window.fetchUsers = fetchUsers;

// Tự động tải dữ liệu ngay khi mở trang
fetchUsers();
