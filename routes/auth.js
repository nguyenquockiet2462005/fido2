/**
 * routes/auth.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 2 (Backend FIDO2)
 * Đã gia cố an ninh, validation, chống replay attack, chống session fixation, chống crash TypeError
 */

import express from 'express';
import crypto from 'crypto';

// Lôi các chuyên gia FIDO2 từ thư viện ra
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

// Kéo các hàm làm việc với dữ liệu người dùng từ db.js
import {
  findUserByUsername,
  findUserByCredentialId,
  createUser,
  addCredentialToUser,
  updateCredentialCounter,
} from '../db.js';

// Tạo một trạm phân luồng (Router)
const router = express.Router();

// Cấu hình định danh cho máy chủ
const rpName = 'FIDO2 Demo';
const rpID = (process.env.RP_ID || 'localhost').trim();
const origin = (process.env.ORIGIN || 'http://localhost:3000').trim().replace(/\/+$/, '');

const isProduction = process.env.NODE_ENV === 'production';

// BẢO MẬT WEBAUTHN (W3C WebAuthn §13.4.1 & OWASP ASVS):
// TRÊN PRODUCTION: CHỈ chấp nhận DUY NHẤT một Origin và một RP ID chính thức để chống Phishing và Relay Attack.
// TRÊN DEVELOPMENT: Cho phép linh hoạt localhost và 127.0.0.1 để tiện kiểm thử cục bộ.
const expectedOrigins = isProduction
  ? [origin]
  : Array.from(new Set([
      origin,
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'https://localhost:3000'
    ]));

const expectedRPIDs = isProduction
  ? [rpID]
  : Array.from(new Set([
      rpID,
      'localhost',
      '127.0.0.1'
    ]));

/**
 * Chuyển đổi userId sang Uint8Array/Buffer phù hợp với chuẩn W3C WebAuthn spec §5.4.3:
 * User handle là chuỗi byte mờ đục (opaque byte sequence) tối đa 64 bytes.
 */
function toUserIdUint8Array(idStr) {
  if (!idStr) {
    return crypto.randomBytes(64);
  }
  if (typeof idStr === 'string') {
    // Nếu là chuỗi base64url đại diện cho 64 random bytes (86 ký tự base64url)
    if (/^[a-zA-Z0-9_-]{86}$/.test(idStr)) {
      return Buffer.from(idStr, 'base64url');
    }
    // Tương thích ngược với các ID dạng chuỗi cũ (admin_seed_...)
    const encoded = new TextEncoder().encode(idStr);
    return encoded.length <= 64 ? encoded : encoded.slice(0, 64);
  }
  return idStr;
}

/**
 * Hàm xác thực tính hợp lệ của Username
 */
function validateUsername(rawUsername) {
  if (!rawUsername || typeof rawUsername !== 'string') {
    return { valid: false, error: 'Vui lòng nhập tên người dùng hợp lệ!' };
  }
  const username = rawUsername.trim();
  if (username.length === 0) {
    return { valid: false, error: 'Vui lòng nhập tên người dùng!' };
  }
  if (username.length < 2 || username.length > 50) {
    return { valid: false, error: 'Tên người dùng phải có từ 2 đến 50 ký tự!' };
  }
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
    return { valid: false, error: 'Tên người dùng chỉ được chứa chữ cái, số, dấu gạch dưới (_), gạch ngang (-) hoặc dấu chấm (.)!' };
  }
  return { valid: true, username };
}

/**
 * So sánh chuỗi an toàn chống tấn công đo lường thời gian (Timing Attack / CWE-208)
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(x, y);
}

// Hạn thời gian sống của Challenge WebAuthn (2 phút theo OWASP/NIST)
const CHALLENGE_TTL_MS = 2 * 60 * 1000;
function isChallengeExpired(createdAt) {
  return !createdAt || (Date.now() - createdAt) > CHALLENGE_TTL_MS;
}

// BẢO MẬT (CWE-532): Tránh log thông tin nhạy cảm (Challenge, Credential) trên production
const debugLog = (...args) => {
  if (!isProduction) console.log(...args);
};



// ==========================================
// GIAI ĐOẠN 1: ĐĂNG KÝ (REGISTRATION)
// ==========================================

// 1. API Tạo Challenge Đăng ký (Ra đề)
router.post('/register-options', async (req, res) => {
  const check = validateUsername(req.body.username);
  if (!check.valid) {
    return res.status(400).json({
      error: check.error
    });
  }
  const username = check.username;

  const existingUser = findUserByUsername(username);

  // BẢO MẬT: Xử lý tài khoản Admin và tài khoản hệ thống bảo lưu
  const isSystemAdmin = username.toLowerCase() === 'admin';
  if (isSystemAdmin) {
    // Nếu tài khoản admin ĐÃ có Passkey rồi -> Khóa tuyệt đối, không cho đăng ký lại
    if (existingUser && existingUser.credentials && existingUser.credentials.length > 0) {
      return res.status(400).json({
        error: 'Tài khoản Admin đã được cài đặt Passkey! Vui lòng bấm Đăng nhập.'
      });
    }
    // BẢO MẬT (C2): Khóa quyền khởi tạo Passkey Admin lần đầu bằng mã cài đặt bí mật (ADMIN_SETUP_TOKEN)
    const requiredToken = process.env.ADMIN_SETUP_TOKEN;
    const providedToken = req.body.setupToken || '';
    if (!requiredToken || !safeEqual(providedToken, requiredToken)) {
      return res.status(403).json({
        error: 'Cần mã cài đặt Admin hợp lệ (ADMIN_SETUP_TOKEN) để khởi tạo tài khoản Quản trị viên!'
      });
    }
    req.session.adminSetupOk = true;
  } else {
    // Với các tài khoản bảo lưu khác
    const OTHER_RESERVED = ['administrator', 'root', 'system'];
    if (OTHER_RESERVED.includes(username.toLowerCase())) {
      return res.status(400).json({
        error: 'Tên tài khoản này được bảo lưu cho quản trị hệ thống, không thể đăng ký mới!'
      });
    }
    // Với người dùng thường: Chặn đăng ký nếu tài khoản đã tồn tại
    if (existingUser) {
      return res.status(400).json({
        error: 'Tên tài khoản này đã tồn tại! Vui lòng chọn tên khác hoặc bấm Đăng nhập.'
      });
    }
  }

  // BẢO MẬT (W3C WebAuthn §5.4.3 & OWASP):
  // Khuyến nghị sử dụng 64 byte ngẫu nhiên mật mã (CSPRNG via crypto.randomBytes)
  // Tuyệt đối không chứa PII (username) hay timestamp dễ đoán (Date.now() + Math.random())
  const userId = (isSystemAdmin && existingUser)
    ? existingUser.id
    : crypto.randomBytes(64).toString('base64url');

  try {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      // Chuyển userID sang Buffer/Uint8Array 64 bytes chuẩn W3C
      userID: toUserIdUint8Array(userId),
      userName: username,
      attestationType: 'none',
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: 'preferred', //'discouraged',
        userVerification: 'required' //'preferred'
      },
    });

    // Ghi nhớ Challenge và thông tin đăng ký tạm vào Session của phiên này
    req.session.currentChallenge = options.challenge;
    req.session.challengeCreatedAt = Date.now();
    req.session.registeringUserId = userId;
    req.session.registeringUsername = username;

    debugLog('==========================================');
    debugLog('[ĐĂNG KÝ] Tạo Challenge thành công');
    debugLog('[ĐĂNG KÝ] Username:', username);
    debugLog('==========================================');

    // Phát đề thi (chuỗi JSON) về cho trình duyệt
    res.json(options);

  } catch (error) {
    console.error("Lỗi khi tạo challenge đăng ký:", error);

    return res.status(500).json({
      error: 'Lỗi hệ thống khi khởi tạo đăng ký.'
    });
  }
});


// 2. API Xác thực Đăng ký (Chấm điểm)
router.post('/register-verify', async (req, res) => {
  const check = validateUsername(req.body.username);
  if (!check.valid) {
    return res.status(400).json({
      verified: false,
      error: check.error
    });
  }
  const username = check.username;
  const { response } = req.body;

  // Kiểm tra response object hợp lệ
  if (!response || typeof response !== 'object' || !response.id) {
    return res.status(400).json({
      verified: false,
      error: 'Dữ liệu phản hồi xác thực sinh trắc học không hợp lệ hoặc bị thiếu!'
    });
  }

  debugLog('==========================================');
  debugLog('[ĐĂNG KÝ] Bắt đầu xác thực');
  debugLog('[ĐĂNG KÝ] Username:', username);
  debugLog('==========================================');

  // Kiểm tra tên gửi lên phải khớp với tên trong phiên đăng ký ban đầu
  if (!req.session.registeringUsername || req.session.registeringUsername.toLowerCase() !== username.toLowerCase()) {
    return res.status(400).json({
      verified: false,
      error: 'Dữ liệu phiên đăng ký không hợp lệ hoặc đã hết hạn!'
    });
  }

  // Lấy lại Đề thi gốc từ trong túi cá nhân (Session) ra để đối chiếu
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({
      verified: false,
      error: 'Không tìm thấy bài thi gốc hoặc phiên đã hết hạn. Vui lòng thử lại!'
    });
  }

  // BẢO MẬT (M1): Kiểm tra thời hạn Challenge đăng ký (2 phút)
  if (isChallengeExpired(req.session.challengeCreatedAt)) {
    req.session.currentChallenge = null;
    req.session.adminSetupOk = false;
    return res.status(400).json({
      verified: false,
      error: 'Phiên đăng ký đã quá hạn (2 phút). Vui lòng thực hiện lại!'
    });
  }

  // Hủy Challenge ngay lập tức để chống tấn công phát lại (Replay Attack)
  req.session.currentChallenge = null;
  req.session.challengeCreatedAt = null;
  const registeringUserId = req.session.registeringUserId;
  req.session.registeringUserId = null;
  req.session.registeringUsername = null;

  try {
    // Nhờ chuyên gia chấm điểm xem lời giải có khớp không
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: expectedRPIDs,
      requireUserVerification: true,
    });

    debugLog('[ĐĂNG KÝ] Kết quả xác thực:', verification.verified);

    if (!verification.verified) {
      return res.status(400).json({
        verified: false,
        error: 'Xác thực Passkey không thành công!'
      });
    }

    const { registrationInfo } = verification;
    const credential = registrationInfo?.credential;

    if (!credential) {
      return res.status(400).json({
        verified: false,
        error: 'Không lấy được thông tin Passkey từ thiết bị!'
      });
    }

    // BẢO MẬT (C2): Khóa quyền khởi tạo Admin nếu chưa qua bước xác thực token hợp lệ
    if (username.toLowerCase() === 'admin') {
      if (!req.session.adminSetupOk) {
        return res.status(403).json({
          verified: false,
          error: 'Chưa được cấp quyền cài đặt tài khoản Quản trị viên!'
        });
      }
      req.session.adminSetupOk = false;
    }

    // Chỉ tạo người dùng chính thức vào DB khi đã quét vân tay thành công!

    let user = findUserByUsername(username);
    if (user) {
      // Trường hợp đặc biệt: Khởi tạo Passkey lần đầu cho tài khoản Admin đã seed (khi chưa có Passkey)
      if (user.username.toLowerCase() === 'admin' && user.role === 'admin' && (!user.credentials || user.credentials.length === 0)) {
        addCredentialToUser(user.username, {
          id: credential.id,
          publicKey: credential.publicKey,
          counter: credential.counter,
          transports: credential.transports || [],
        });
        console.log('🛡️ [ADMIN] Khởi tạo Passkey ban đầu cho Quản trị viên thành công!');
        return res.json({
          verified: true,
          message: 'Khởi tạo Passkey Admin thành công! Vui lòng bấm Đăng nhập.'
        });
      }

      return res.status(400).json({
        verified: false,
        error: 'Tài khoản này đã tồn tại. Không thể đăng ký đè Passkey!'
      });
    }

    // BẢO MẬT: Chặn gán passkey cho các tài khoản hệ thống bảo lưu khác
    const OTHER_RESERVED = ['administrator', 'root', 'system'];
    if (OTHER_RESERVED.includes(username.toLowerCase())) {
      return res.status(400).json({
        verified: false,
        error: 'Tên tài khoản này được bảo lưu cho quản trị hệ thống, không thể đăng ký mới!'
      });
    }
    // Tạo tài khoản mới hoàn toàn
    user = createUser(username, registeringUserId);
    addCredentialToUser(user.username, {
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
    });


    console.log('==========================================');
    console.log('[ĐĂNG KÝ] Lưu Passkey thành công!');
    console.log('[ĐĂNG KÝ] Credential ID:', credential.id);
    console.log('==========================================');

    return res.json({
      verified: true,
      message: 'Đăng ký sinh trắc học thành công!'
    });

  } catch (error) {
    console.error('==========================================');
    console.error('[ĐĂNG KÝ] LỖI XÁC THỰC');
    console.error(error);
    console.error('==========================================');

    return res.status(400).json({
      verified: false,
      error: error.message || 'Xác thực Passkey thất bại.'
    });
  }
});


// ==========================================
// GIAI ĐOẠN 2: ĐĂNG NHẬP (AUTHENTICATION)
// ==========================================

// 3. API Tạo Challenge Đăng nhập (Hỗ trợ cả có Username lẫn Usernameless 1-chạm)
router.post('/login-options', async (req, res) => {
  const rawUsername = req.body.username;
  const isUsernameless = !rawUsername || typeof rawUsername !== 'string' || rawUsername.trim() === '';

  let user = null;
  let userCredentials = [];

  if (!isUsernameless) {
    const check = validateUsername(rawUsername);
    if (!check.valid) {
      return res.status(400).json({
        error: check.error
      });
    }
    const username = check.username;
    user = findUserByUsername(username);

    if (!user) {
      return res.status(404).json({
        error: 'Tài khoản không tồn tại!'
      });
    }

    userCredentials = user.credentials || [];
    if (userCredentials.length === 0) {
      return res.status(400).json({
        error: 'Tài khoản này chưa cài đặt sinh trắc học!'
      });
    }
  }

  try {
    const optsConfig = {
      rpID,
      userVerification: 'required',
    };

    // Nếu có username: giới hạn khóa thuộc về tài khoản đó (Luồng truyền thống)
    // Nếu không có username: bỏ qua allowCredentials để trình duyệt tự mở kho Passkey trên thiết bị (Luồng 1-chạm)
    if (!isUsernameless) {
      optsConfig.allowCredentials = userCredentials.map(dev => ({
        id: dev.id,
        type: 'public-key',
        transports: dev.transports || [],
      }));
    }

    const options = await generateAuthenticationOptions(optsConfig);

    req.session.currentChallenge = options.challenge;
    req.session.challengeCreatedAt = Date.now();
    req.session.loginUsername = user ? user.username : null;

    debugLog('==========================================');
    debugLog(`[ĐĂNG NHẬP${isUsernameless ? ' NHANH 1-CHẠM' : ''}] Tạo Challenge thành công`);
    if (user) debugLog('[ĐĂNG NHẬP] Username:', user.username);
    debugLog('==========================================');

    res.json(options);

  } catch (error) {
    console.error("Lỗi khi tạo challenge đăng nhập:", error);

    return res.status(500).json({
      error: 'Lỗi hệ thống khi khởi tạo đăng nhập.'
    });
  }
});


// 4. API Xác thực Đăng nhập (Chấm điểm - Hỗ trợ cả 2 luồng)
router.post('/login-verify', async (req, res) => {
  const { response, username: rawUsername } = req.body;

  // PHÒNG CHỐNG CRASH TYPEERROR: Kiểm tra chặt chẽ object response trước khi truy xuất response.id
  if (!response || typeof response !== 'object' || !response.id) {
    return res.status(400).json({
      verified: false,
      error: 'Dữ liệu chữ ký sinh trắc học không hợp lệ hoặc bị thiếu!'
    });
  }

  let user = null;
  const isUsernameless = !rawUsername || typeof rawUsername !== 'string' || rawUsername.trim() === '';

  if (!isUsernameless) {
    const check = validateUsername(rawUsername);
    if (!check.valid) {
      return res.status(400).json({
        verified: false,
        error: check.error
      });
    }
    user = findUserByUsername(check.username);
  } else {
    // Luồng Usernameless 1-chạm: Tìm người dùng trong database theo Credential ID
    user = findUserByCredentialId(response.id);
  }

  if (!user) {
    return res.status(404).json({
      verified: false,
      error: isUsernameless
        ? 'Không tìm thấy tài khoản gắn với Passkey trên thiết bị này!'
        : 'Tài khoản không tồn tại!'
    });
  }

  debugLog('==========================================');
  debugLog(`[ĐĂNG NHẬP${isUsernameless ? ' NHANH 1-CHẠM' : ''}] Bắt đầu xác thực`);
  debugLog('[ĐĂNG NHẬP] Username:', user.username);
  debugLog('==========================================');

  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({
      verified: false,
      error: 'Phiên đăng nhập hết hạn hoặc challenge không hợp lệ. Vui lòng làm lại!'
    });
  }

  // BẢO MẬT (M1): Kiểm tra thời hạn Challenge đăng nhập (2 phút)
  if (isChallengeExpired(req.session.challengeCreatedAt)) {
    req.session.currentChallenge = null;
    req.session.challengeCreatedAt = null;
    return res.status(400).json({
      verified: false,
      error: 'Phiên đăng nhập đã quá hạn (2 phút). Vui lòng thử lại!'
    });
  }

  // Hủy Challenge ngay lập tức để chống Replay Attack
  req.session.currentChallenge = null;
  req.session.challengeCreatedAt = null;

  const userCredentials = user.credentials || [];

  const currentDevice = userCredentials.find(
    device => device.id === response.id
  );

  if (!currentDevice) {
    return res.status(400).json({
      verified: false,
      error: 'Thiết bị này chưa được đăng ký vân tay/FaceID cho tài khoản!'
    });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: expectedRPIDs,
      credential: {
        id: currentDevice.id,
        publicKey: currentDevice.publicKey,
        counter: currentDevice.counter,
        transports: currentDevice.transports || [],
      },
      requireUserVerification: true,
    });

    console.log('[ĐĂNG NHẬP] Kết quả xác thực:', verification.verified);

    if (!verification.verified) {
      return res.status(400).json({
        verified: false,
        error: 'Xác thực đăng nhập thất bại!'
      });
    }

    const { authenticationInfo } = verification;

    updateCredentialCounter(
      user.username,
      currentDevice.id,
      authenticationInfo.newCounter
    );

    // CHỐNG SESSION FIXATION: Tái tạo session ID mới khi đăng nhập thành công
    req.session.regenerate((err) => {
      if (err) {
        console.error('Lỗi tái tạo session ID:', err);
      }
      req.session.loggedIn = true;
      req.session.username = user.username;
      // Phân quyền chuẩn xác theo role đã lưu trong cơ sở dữ liệu
      req.session.role = user.role === 'admin' ? 'admin' : 'student';

      console.log('==========================================');
      console.log('[ĐĂNG NHẬP] Đăng nhập thành công!');
      console.log(`[ĐĂNG NHẬP] User: ${user.username} | Role: ${req.session.role}`);
      console.log('==========================================');

      return res.json({
        verified: true,
        message: 'Đăng nhập thành công! Chào mừng trở lại.',
        user: {
          username: user.username,
          role: req.session.role
        }
      });
    });

  } catch (error) {
    console.error('=========================================');
    console.error('[ĐĂNG NHẬP] LỖI XÁC THỰC');
    console.error(error);
    console.error('=========================================');

    return res.status(400).json({
      verified: false,
      error: error.message || 'Xác thực đăng nhập thất bại!'
    });
  }
});

export default router;