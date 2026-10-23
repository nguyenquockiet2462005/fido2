/**
 * server.js - Điểm khởi đầu chính của ứng dụng Backend
 * 
 * VAI TRÒ CỦA FILE NÀY:
 * 1. Khởi động Web Server Express.
 * 2. Cấu hình Express-Session để bảo vệ Challenge và trạng thái đăng nhập.
 * 3. Phục vụ giao diện người dùng tĩnh từ thư mục `public/`.
 * 4. Cung cấp các API kiểm tra trạng thái an toàn (Health check & Phân quyền Admin).
 */

// Tự động nạp file .env nếu có (Node.js 20+)
if (typeof process.loadEnvFile === 'function') {
  try { process.loadEnvFile(); } catch (_) {}
}

import express from 'express';
import session from 'express-session';
import path from 'path';
import { fileURLToPath } from 'url';
import { getAllUsers, initMongoDB } from './db.js';
import authRoutes from './routes/auth.js';
import userRoutes from './routes/user.js';

// Cần thiết để lấy đường dẫn thư mục hiện tại khi dùng ES Module ("type": "module")
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. CẤU HÌNH MIDDLEWARE ĐỌC DỮ LIỆU
// ==========================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// 2. CẤU HÌNH EXPRESS-SESSION (BẢO MẬT PHIÊN)
// ==========================================
app.set('trust proxy', 1);
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'fido2-nhom-bi-mat-khong-the-doan-duoc-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // BẢO MẬT: Ngăn chặn XSS đọc trộm cookie
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000, // 24 giờ
    },
  })
);

// ==========================================
// 3. PHỤC VỤ THƯ VIỆN BROWSER NỘI BỘ & TĨNH
// ==========================================
// Phục vụ trực tiếp thư viện SimpleWebAuthnBrowser v14 từ node_modules để đảm bảo chạy mượt mà ngay cả khi offline
app.get('/vendor/simplewebauthn-browser.min.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js'));
});

// Phục vụ giao diện tĩnh từ public/
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 4. CÁC ROUTE CƠ BẢN ĐỂ KIỂM TRA (HEALTH & ADMIN)
// ==========================================

// Route kiểm tra xem Server có đang hoạt động tốt hay không
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'FIDO2 Demo Server đang hoạt động an toàn',
    timestamp: new Date().toISOString(),
  });
});

// Route kiểm tra trạng thái phiên làm việc hiện tại (BẢO MẬT: Không để lộ SessionID raw)
app.get('/api/session-debug', (req, res) => {
  res.json({
    hasSession: !!req.session,
    loggedIn: !!req.session?.loggedIn,
    currentUser: req.session?.username || null,
    currentRole: req.session?.role || null,
    currentChallenge: req.session?.currentChallenge ? 'Đang lưu Challenge bảo mật trong RAM' : null,
  });
});

// Route xem danh sách người dùng trong RAM (BẢO MẬT: Chỉ Admin mới được truy cập để chống rò rỉ dữ liệu)
app.get('/api/users-debug', (req, res) => {
  if (!req.session?.loggedIn || req.session?.role !== 'admin') {
    return res.status(403).json({
      error: 'Từ chối truy cập: Chỉ Admin mới có quyền xem thông tin chi tiết người dùng!'
    });
  }

  const all = getAllUsers();
  const sanitized = all.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    profile: u.profile,
    credentialsCount: (u.credentials || []).length,
    credentialsMeta: (u.credentials || []).map(c => ({
      id: c.id,
      counter: c.counter,
      transports: c.transports
    }))
  }));

  res.json({
    totalUsers: sanitized.length,
    users: sanitized,
  });
});

// Route dành riêng cho Admin Dashboard - chỉ cho phép tài khoản có role 'admin'
app.get('/api/users', (req, res) => {
  if (!req.session?.loggedIn) {
    return res.status(401).json({ error: 'Chưa đăng nhập!' });
  }
  if (req.session?.role !== 'admin') {
    return res.status(403).json({ error: 'Không có quyền Admin!' });
  }
  const usersArr = getAllUsers();
  const sanitized = usersArr.map(u => ({
    id: u.id,
    username: u.username,
    role: u.role,
    hoTen: u.profile?.fullName || u.username,
    ngaySinh: u.profile?.dob || '--/--/----',
    profile: u.profile,
    credentials: (u.credentials || []).map(c => ({
      id: c.id,
      counter: c.counter,
      transports: c.transports
    })),
  }));
  res.json(sanitized);
});

// Route Đăng xuất (Xóa Session an toàn)
app.post('/api/auth/logout', (req, res) => {
  if (!req.session) {
    res.clearCookie('connect.sid');
    return res.json({ success: true, message: 'Đã đăng xuất.' });
  }
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Không thể đăng xuất' });
    }
    res.clearCookie('connect.sid');
    return res.json({ success: true, message: 'Đăng xuất thành công!' });
  });
});

// Gắn toàn bộ các API FIDO2 vào tiền tố /api/auth và /api/user
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);

// ==========================================
// 5. KHỞI ĐỘNG SERVER
// ==========================================
// Chỉ tự động listen khi chạy trực tiếp file server.js (tránh chiếm cổng khi chạy unit test)
const isMainModule = process.argv[1] && (
  process.argv[1].endsWith('server.js') ||
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
);

if (isMainModule) {
  await initMongoDB();
  app.listen(PORT, () => {
    console.log('====================================================');
    console.log(`Server FIDO2 đang chạy tại: http://localhost:${PORT}`);
    console.log(`Thư mục giao diện phục vụ từ: ${path.join(__dirname, 'public')}`);
    console.log('====================================================');
  });
}

export default app;
export { app };