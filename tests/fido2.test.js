import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { app } from '../server.js';
import { findUserByUsername, createUser, claimStudentIdentity, unlinkStudentCard } from '../db.js';

describe('BỘ KIỂM THỬ TOÀN DIỆN HỆ THỐNG XÁC THỰC FIDO2 & BẢO MẬT HUTECH', () => {
  let server;
  let baseUrl;

  before(async () => {
    // Chạy server trên cổng ngẫu nhiên (ephemeral port) để tránh xung đột
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => {
      server.close(resolve);
    });
  });

  // =========================================================================
  // 1. KIỂM THỬ HEALTH CHECK & BẢO MẬT SESSION DEBUG
  // =========================================================================
  describe('1. Health Check & Session Debug', () => {
    it('GET /api/health phải trả về trạng thái ok 200', async () => {
      const res = await fetch(`${baseUrl}/api/health`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.status, 'ok');
    });

    it('GET /api/session-debug không được để lộ SessionID raw (chống Session Hijacking)', async () => {
      const res = await fetch(`${baseUrl}/api/session-debug`);
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.sessionID, undefined, 'Session ID không được trả về trong JSON');
      assert.equal(typeof data.loggedIn, 'boolean');
    });
  });

  // =========================================================================
  // 2. KIỂM THỬ KIỂM SOÁT TRUY CẬP & CHỐNG RÒ RỈ DỮ LIỆU
  // =========================================================================
  describe('2. Phân quyền & Chống rò rỉ dữ liệu', () => {
    it('GET /api/users-debug bị chặn 403 khi chưa đăng nhập Admin', async () => {
      const res = await fetch(`${baseUrl}/api/users-debug`);
      assert.equal(res.status, 403, 'Người dùng vãng lai không được phép xem users-debug');
    });

    it('GET /api/users bị chặn 401 khi chưa đăng nhập', async () => {
      const res = await fetch(`${baseUrl}/api/users`);
      assert.equal(res.status, 401);
    });

    it('DELETE /api/user/profile/unlink-card bị chặn 403 (bắt buộc Step-up Passkey)', async () => {
      const res = await fetch(`${baseUrl}/api/user/profile/unlink-card`, { method: 'DELETE' });
      assert.equal(res.status, 403);
      const data = await res.json();
      assert.match(data.error, /Hành động nhạy cảm/);
    });
  });

  // =========================================================================
  // 3. KIỂM THỬ TẠO CHALLENGE ĐĂNG KÝ (INPUT VALIDATION)
  // =========================================================================
  describe('3. Đăng ký Passkey - Kiểm tra lỗi đầu vào (Input Validation)', () => {
    it('Chặn khi username là rỗng', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Vui lòng nhập tên người dùng/);
    });

    it('Chặn khi username chỉ toàn khoảng trắng "   "', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '     ' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /Vui lòng nhập tên người dùng/);
    });

    it('Chặn khi username là kiểu dữ liệu số hoặc object', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 123456 })
      });
      assert.equal(res.status, 400);
    });

    it('Chặn khi username quá ngắn (< 2 ký tự)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'a' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /từ 2 đến 50 ký tự/);
    });

    it('Chặn khi username chứa ký tự đặc biệt nguy hiểm (XSS injection)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: '<script>alert(1)</script>' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /chỉ được chứa chữ cái/);
    });

    it('Chặn khi đăng ký trùng tên với tài khoản đã có Passkey', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'kiet' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /đã được đăng ký/);
    });

    it('Thành công tạo challenge khi username hợp lệ', async () => {
      const newUsername = 'test_user_' + Date.now();
      const res = await fetch(`${baseUrl}/api/auth/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: newUsername })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.challenge);
      assert.ok(data.user);
      assert.equal(data.rp.name, 'FIDO2 Demo');
    });

    it('Chống leo thang đặc quyền: Đăng ký username bắt đầu bằng admin (vd: admin_vip) KHÔNG được gán quyền Admin', async () => {
      const prefixAdminUsername = 'admin_vip_' + Date.now();
      const user = createUser(prefixAdminUsername);
      assert.equal(user.role, 'student', 'Tài khoản đăng ký mới phải là student, không thể tự phong admin qua tiền tố!');
    });
  });

  // =========================================================================
  // 4. KIỂM THỬ XÁC MINH ĐĂNG KÝ (REGISTER VERIFY)
  // =========================================================================
  describe('4. Xác minh Đăng ký Passkey - Xử lý lỗi', () => {
    it('Trả về 400 khi thiếu object response hoặc response rỗng', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'testuser' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.verified, false);
      assert.match(data.error, /phản hồi xác thực/);
    });

    it('Trả về 400 khi không có Challenge gốc trong Session', async () => {
      const res = await fetch(`${baseUrl}/api/auth/register-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'testuser',
          response: { id: 'dummy_id' }
        })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.equal(data.verified, false);
      assert.match(data.error, /phiên đăng ký không hợp lệ|hết hạn/);
    });
  });

  // =========================================================================
  // 5. KIỂM THỬ TẠO CHALLENGE ĐĂNG NHẬP (LOGIN OPTIONS)
  // =========================================================================
  describe('5. Đăng nhập Passkey - Tạo Challenge', () => {
    it('Chặn khi username không tồn tại trong hệ thống (404)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'non_existent_user_99999' })
      });
      assert.equal(res.status, 404);
      const data = await res.json();
      assert.match(data.error, /không tồn tại/);
    });

    it('Chặn khi tài khoản có tồn tại nhưng chưa có Passkey (400)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'abcd123' })
      });
      assert.equal(res.status, 400);
      const data = await res.json();
      assert.match(data.error, /chưa cài đặt sinh trắc học/);
    });

    it('Thành công tạo options khi tài khoản hợp lệ đã có Passkey (kiet)', async () => {
      const res = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'kiet' })
      });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.ok(data.challenge);
      assert.ok(Array.isArray(data.allowCredentials));
      assert.ok(data.allowCredentials.length > 0);
    });
  });

  // =========================================================================
  // 6. KIỂM THỬ XÁC MINH ĐĂNG NHẬP & PHÒNG CHỐNG CRASH SERVER
  // =========================================================================
  describe('6. Đăng nhập Passkey - Xác minh & Chống crash Server', () => {
    it('CHỐNG CRASH 500: Server không bị crash khi client gửi login-verify mà thiếu trường response', async () => {
      // 1. Tạo session login trước
      const optRes = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'kiet' })
      });
      const cookie = optRes.headers.get('set-cookie');
      assert.equal(optRes.status, 200);

      // 2. Gửi login-verify không có response (trước đây bị TypeError unhandled văng 500)
      const verRes = await fetch(`${baseUrl}/api/auth/login-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie
        },
        body: JSON.stringify({ username: 'kiet' }) // thiếu response!
      });

      assert.equal(verRes.status, 400, 'Server phải trả về 400 hợp lệ, KHÔNG được crash 500!');
      const data = await verRes.json();
      assert.equal(data.verified, false);
      assert.match(data.error, /chữ ký sinh trắc học/);
    });

    it('Trả về 400 khi thiết bị không khớp với Credential đã đăng ký', async () => {
      const optRes = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'kiet' })
      });
      const cookie = optRes.headers.get('set-cookie');

      const verRes = await fetch(`${baseUrl}/api/auth/login-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': cookie
        },
        body: JSON.stringify({
          username: 'kiet',
          response: { id: 'unregistered_device_credential_id_xyz' }
        })
      });

      assert.equal(verRes.status, 400);
      const data = await verRes.json();
      assert.match(data.error, /chưa được đăng ký/);
    });

    it('Chống Replay Attack: Challenge bị hủy ngay sau lần verify đầu tiên, không thể thử lại', async () => {
      const optRes = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'kiet' })
      });
      const cookie = optRes.headers.get('set-cookie');

      // Lần 1: Sai chữ ký
      await fetch(`${baseUrl}/api/auth/login-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': cookie },
        body: JSON.stringify({ username: 'kiet', response: { id: '9Z7PnPczOC4N_umkDlDjNmkcC_8' } })
      });

      // Lần 2: Thử lại với cùng session cookie -> Phải bị từ chối vì Challenge đã bị hủy
      const res2 = await fetch(`${baseUrl}/api/auth/login-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': cookie },
        body: JSON.stringify({ username: 'kiet', response: { id: '9Z7PnPczOC4N_umkDlDjNmkcC_8' } })
      });

      assert.equal(res2.status, 400);
      const data2 = await res2.json();
      assert.match(data2.error, /hết hạn hoặc challenge không hợp lệ/);
    });
  });

  // =========================================================================
  // 7. KIỂM THỬ XÁC THỰC THẺ SINH VIÊN & THU HỒI DANH TÍNH
  // =========================================================================
  describe('7. Quét thẻ sinh viên vật lý & Bảo vệ danh tính chính chủ', () => {
    it('Chặn xác thực thẻ khi chưa đăng nhập (401)', async () => {
      const res = await fetch(`${baseUrl}/api/user/profile/verify-card`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ studentId: '2180601234' })
      });
      assert.equal(res.status, 401);
    });

    it('Chặn chiếm đoạt MSSV khi sinh viên khác đã kích hoạt thẻ thành công', () => {
      const userA = createUser('sinhvien_a_' + Date.now());
      const userB = createUser('sinhvien_b_' + Date.now());
      const testMssv = '2180' + Math.floor(100000 + Math.random() * 900000);

      // A kích hoạt thành công
      claimStudentIdentity(userA.username, {
        studentId: testMssv,
        fullName: 'Nguyễn Văn A',
        dob: '10/10/2003'
      });

      // B cố tình chiếm đoạt MSSV của A
      assert.throws(() => {
        claimStudentIdentity(userB.username, {
          studentId: testMssv,
          fullName: 'Kẻ Mạo Danh B',
          dob: '11/11/2003'
        });
      }, /đã được kích hoạt bởi tài khoản chính chủ khác/);
    });

    it('Chặn cùng một tài khoản liên kết sang thẻ sinh viên của người khác', () => {
      const userC = createUser('sinhvien_c_' + Date.now());
      const mssv1 = '2180' + Math.floor(100000 + Math.random() * 900000);
      const mssv2 = '2180' + Math.floor(100000 + Math.random() * 900000);

      claimStudentIdentity(userC.username, { studentId: mssv1, fullName: 'Sinh Viên C' });

      assert.throws(() => {
        claimStudentIdentity(userC.username, { studentId: mssv2, fullName: 'Sinh Viên C' });
      }, /không thể liên kết thẻ của sinh viên khác/);
    });
  });

  // =========================================================================
  // 8. KIỂM THỬ ĐĂNG XUẤT (LOGOUT)
  // =========================================================================
  describe('8. Đăng xuất an toàn', () => {
    it('POST /api/auth/logout xóa sạch session và trả về thành công', async () => {
      const res = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST' });
      assert.equal(res.status, 200);
      const data = await res.json();
      assert.equal(data.success, true);
    });
  });
});
