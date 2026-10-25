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
  try { process.loadEnvFile(); } catch (_) { }
}

import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import rateLimit from 'express-rate-limit';
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
// 2. BẢO MẬT KHÓA SESSION_SECRET (CHỐNG CWE-798 HARDCODED SECRET)
// ==========================================
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  if (process.env.NODE_ENV === 'production') {
    console.error('❌ [BẢO MẬT PRODUCTION] LỖI NGHIÊM TRỌNG: Thiếu biến môi trường SESSION_SECRET!');
    console.error('   Server từ chối chạy với secret mặc định để chống giả mạo Cookie phiên (CWE-798).');
    process.exit(1);
  } else {
    // Trong môi trường Local Dev: Sinh ngẫu nhiên trong RAM, không để lộ chuỗi tĩnh trên Git
    sessionSecret = crypto.randomBytes(32).toString('hex');
    console.warn('⚠️ [BẢO MẬT DEV] Không phát hiện SESSION_SECRET trong file .env.');
    console.warn('   -> Đã tự động sinh Secret ngẫu nhiên bảo mật trong RAM cho phiên chạy này.');
  }
}

// ==========================================
// 3. CẤU HÌNH SESSION STORE (MONGOSTORE PERSISTENCE)
// Tránh Memory Leak & bảo toàn phiên khi Render khởi động lại
// ==========================================
let sessionStore = undefined;
if (process.env.MONGODB_URI) {
  sessionStore = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60, // 24 giờ
    autoRemove: 'native'
  });
  console.log('🍃 [SESSION] Đã kích hoạt MongoStore (Lưu trữ phiên trên MongoDB Atlas vĩnh viễn)');
} else {
  console.warn('⚠️ [SESSION] Không có MONGODB_URI. Sử dụng MemoryStore tạm thời (Chỉ dùng cho Local Dev)');
}

app.set('trust proxy', 1);
app.use(
  session({
    secret: sessionSecret,
    store: sessionStore,
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
// 4. RATE LIMITING (GIỚI HẠN TẦN SUẤT GỌI API - CHỐNG DOS/DDOS)
// ==========================================
// Giới hạn chung cho toàn bộ API
const globalApiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 phút
  max: 300, // Tối đa 300 yêu cầu/15 phút trên mỗi IP
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api', globalApiLimiter);

// Giới hạn nghiêm ngặt cho các API xác thực nhạy cảm (Đăng ký, Đăng nhập, Challenge FIDO2)
const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 phút
  max: 40, // Tối đa 40 yêu cầu/5 phút trên mỗi IP (đủ thoải mái cho người dùng thật nhưng chặn bot spam)
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    verified: false,
    error: 'Quá nhiều yêu cầu xác thực từ IP của bạn. Vui lòng thử lại sau 5 phút!'
  }
});

// ==========================================
// 5. PHỤC VỤ THƯ VIỆN BROWSER NỘI BỘ & TĨNH
// ==========================================
app.get('/vendor/simplewebauthn-browser.min.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js'));
});

// Phục vụ giao diện tĩnh từ public/ (tắt cache ở môi trường dev để trình duyệt luôn nhận file JS mới nhất)
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    if (process.env.NODE_ENV !== 'production') {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

// ==========================================
// 6. CÁC ROUTE KIỂM TRA (HEALTH, ADMIN & DEBUG AN TOÀN)
// ==========================================

// Route kiểm tra sức khỏe hệ thống
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'FIDO2 Demo Server đang hoạt động an toàn',
    env: process.env.NODE_ENV || 'development',
    sessionStore: sessionStore ? 'MongoStore' : 'MemoryStore',
    timestamp: new Date().toISOString(),
  });
});

// BẢO MẬT CWE-200: Chỉ kích hoạt route debug khi chạy ở môi trường DEV
// Trên Production sẽ trả về 404 để chống rò rỉ thông tin hệ thống cho kẻ tấn công
if (process.env.NODE_ENV !== 'production') {
  console.log('🛠️ [DEV-MODE] Đang bật các route debug nội bộ (/api/session-debug, /api/users-debug)');

  app.get('/api/session-debug', (req, res) => {
    res.json({
      hasSession: !!req.session,
      loggedIn: !!req.session?.loggedIn,
      currentUser: req.session?.username || null,
      currentRole: req.session?.role || null,
      storeType: sessionStore ? 'MongoStore (Persistent)' : 'MemoryStore (Volatile)',
      currentChallenge: req.session?.currentChallenge ? 'Đang lưu Challenge bảo mật' : null,
    });
  });

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
} else {
  // Trên Production: Trả về 404 cho mọi truy vấn debug
  app.all(['/api/session-debug', '/api/users-debug'], (req, res) => {
    res.status(404).json({ error: 'Endpoint không tồn tại hoặc đã bị vô hiệu hóa trên môi trường Production.' });
  });
}

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

// Gắn toàn bộ các API FIDO2 vào tiền tố /api/auth (kèm authLimiter) và /api/user
app.use('/api/auth', authLimiter, authRoutes);
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