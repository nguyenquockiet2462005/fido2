/**
 * server.js - Điểm khởi đầu chính của ứng dụng Backend
 * 
 * VAI TRÒ CỦA FILE NÀY:
 * 1. Khởi động Web Server Express.
 * 2. Cấu hình Express-Session để bảo vệ Challenge và trạng thái đăng nhập.
 * 3. Phục vụ giao diện người dùng tĩnh từ thư mục `public/`.
 * 4. Cung cấp các API kiểm tra trạng thái (Health check & Debug session).
 */

import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import { getAllUsers } from './db.js';
import authRoutes from './routes/auth.js'; // Nhập các API xác thực do Thành viên 2 phụ trách

// Cần thiết để lấy đường dẫn thư mục hiện tại khi dùng ES Module ("type": "module")
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. CẤU HÌNH MIDDLEWARE ĐỌC DỮ LIỆU
// ==========================================
// Cho phép Express tự động chuyển đổi dữ liệu gửi lên dạng JSON thành đối tượng JavaScript `req.body`
// (WebAuthn gửi và nhận các chuỗi khóa công khai hoàn toàn bằng định dạng JSON)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// 2. CẤU HÌNH EXPRESS-SESSION (BẢO MẬT PHIÊN)
// ==========================================
/**
 * TẠI SAO PHẢI CÓ SESSION TRONG FIDO2?
 * - Khi người dùng bấm Đăng ký hoặc Đăng nhập, Server tạo ra 1 chuỗi bí mật ngẫu nhiên gọi là `challenge`.
 * - Server phải cất `challenge` này vào Session (`req.session.currentChallenge`).
 * - Khi trình duyệt quét vân tay xong và gửi chữ ký về, Server mở Session ra lấy `challenge` cũ đối chiếu.
 * - Nếu không có Session, Server không thể nhớ được mình đã phát ra Challenge nào, dễ bị tấn công Replay Attack.
 */
app.use(
  session({
    // Khóa bí mật dùng để ký và mã hóa Session ID cookie, ngăn ngừa giả mạo cookie
    secret: 'fido2-nhom-bi-mat-khong-the-doan-duoc-2026',

    // `resave: false`: Không lưu lại session nếu không có dữ liệu mới thay đổi (giúp tối ưu hiệu năng)
    resave: false,

    // `saveUninitialized: false`: Chỉ tạo session khi chúng ta chủ động lưu dữ liệu (tiết kiệm bộ nhớ RAM)
    saveUninitialized: false,

    cookie: {
      // `httpOnly: true`: BẢO MẬT CAO - Ngăn không cho mã độc JavaScript (XSS) trên trình duyệt đọc trộm cookie
      httpOnly: true,

      // `secure: false`: Đặt là false vì ta đang chạy thử nghiệm cục bộ với HTTP (http://localhost:3000)
      // (Khi đưa lên môi trường thật có tên miền và HTTPS thì mới bật là true)
      secure: false,

      // Thời hạn tồn tại của phiên: 24 giờ
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// ==========================================
// 3. PHỤC VỤ GIAO DIỆN TĨNH (STATIC FILES)
// ==========================================
// Khi người dùng mở http://localhost:3000, Express sẽ tự động phục vụ file `public/index.html`
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 4. CÁC ROUTE CƠ BẢN ĐỂ KIỂM TRA (DEBUG & TEST)
// ==========================================

// Route kiểm tra xem Server có đang hoạt động tốt hay không
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'FIDO2 Demo Server đang hoạt động',
    timestamp: new Date().toISOString(),
  });
});

// Route kiểm tra trạng thái phiên làm việc hiện tại (Ai đang đăng nhập? Challenge hiện tại là gì?)
app.get('/api/session-debug', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    loggedIn: !!req.session.loggedIn,
    currentUser: req.session.username || null,
    currentChallenge: req.session.currentChallenge ? 'Đang lưu Challenge bảo mật trong RAM' : null,
  });
});

// Route xem danh sách người dùng trong RAM (Giúp nhóm quan sát xem Passkey đã lưu vào chưa)
app.get('/api/users-debug', (req, res) => {
  res.json({
    totalUsers: getAllUsers().length,
    users: getAllUsers(),
  });
});

// Route Đăng xuất (Xóa Session)
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Không thể đăng xuất' });
    }
    // Xóa cookie phiên trên trình duyệt
    res.clearCookie('connect.sid');
    return res.json({ success: true, message: 'Đăng xuất thành công!' });
  });
});

// Gắn toàn bộ các API FIDO2 (Đăng ký, Đăng nhập) do Thành viên 2 viết vào tiền tố /api/auth
app.use('/api/auth', authRoutes);

// ==========================================
// 5. KHỞI ĐỘNG SERVER
// ==========================================
app.listen(PORT, () => {
  console.log('====================================================');
  console.log(`🚀 Server FIDO2 đang chạy tại: http://localhost:${PORT}`);
  console.log(`📁 Thư mục giao diện phục vụ từ: ${path.join(__dirname, 'public')}`);
  console.log('====================================================');
});