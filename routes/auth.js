/**
 * routes/auth.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 2 (Backend FIDO2)
 * Đã gia cố an ninh, validation, chống replay attack, chống session fixation, chống crash TypeError
 */

import express from 'express';

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
  createUser,
  addCredentialToUser,
  updateCredentialCounter,
} from '../db.js';

// Tạo một trạm phân luồng (Router)
const router = express.Router();

// Cấu hình định danh cho máy chủ
const rpName = 'FIDO2 Demo';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:3000';

// Hỗ trợ cả localhost và 127.0.0.1 để tránh lỗi mismatch Origin khi test cục bộ
const expectedOrigins = Array.from(new Set([
  origin,
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://localhost:3000'
]));

const expectedRPIDs = Array.from(new Set([
  rpID,
  'localhost',
  '127.0.0.1'
]));

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

  // BẢO MẬT: Chặn đăng ký các username hệ thống bảo lưu (Reserved Usernames)
  const RESERVED_USERNAMES = ['admin', 'administrator', 'root', 'system'];
  if (RESERVED_USERNAMES.includes(username.toLowerCase())) {
    return res.status(400).json({
      error: 'Tên tài khoản này được bảo lưu cho quản trị hệ thống, không thể đăng ký mới!'
    });
  }

  // Kiểm tra tài khoản đã tồn tại trong cơ sở dữ liệu chưa
  const existingUser = findUserByUsername(username);
  if (existingUser) {
    return res.status(400).json({
      error: 'Tên tài khoản này đã tồn tại! Vui lòng chọn tên khác hoặc bấm Đăng nhập.'
    });
  }

  // Tạo ID tạm thời trong RAM cho người dùng mới (KHÔNG gọi createUser vào DB lúc này!)
  const userId = `user_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  try {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      // Chuyển chuỗi văn bản sang Uint8Array theo đúng chuẩn SimpleWebAuthn v14
      userID: new TextEncoder().encode(userId),
      userName: username,
      attestationType: 'none',
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred'
      },
    });

    // Ghi nhớ Challenge và thông tin đăng ký tạm vào Session của phiên này
    req.session.currentChallenge = options.challenge;
    req.session.challengeCreatedAt = Date.now();
    req.session.registeringUserId = userId;
    req.session.registeringUsername = username;

    // In ra Terminal để nhóm dễ theo dõi quá trình
    console.log('==========================================');
    console.log('[ĐĂNG KÝ] Tạo Challenge thành công');
    console.log('[ĐĂNG KÝ] Username:', username);
    console.log('[ĐĂNG KÝ] Challenge:', options.challenge);
    console.log('==========================================');

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

  console.log('==========================================');
  console.log('[ĐĂNG KÝ] Bắt đầu xác thực');
  console.log('[ĐĂNG KÝ] Username:', username);
  console.log('[ĐĂNG KÝ] Credential ID:', response.id);
  console.log('==========================================');

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

  // Hủy Challenge ngay lập tức để chống tấn công phát lại (Replay Attack)
  req.session.currentChallenge = null;
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
    });

    console.log('[ĐĂNG KÝ] Kết quả xác thực:', verification.verified);

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

    // Chỉ tạo người dùng chính thức vào DB khi đã quét vân tay thành công!

    // BẢO MẬT: Chặn gán passkey cho các tài khoản hệ thống bảo lưu
    const RESERVED_USERNAMES = ['admin', 'administrator', 'root', 'system'];
    if (RESERVED_USERNAMES.includes(username.toLowerCase())) {
      return res.status(400).json({
        verified: false,
        error: 'Tên tài khoản này được bảo lưu cho quản trị hệ thống, không thể đăng ký mới!'
      });
    }

    let user = findUserByUsername(username);
    if (user) {
      return res.status(400).json({
        verified: false,
        error: 'Tài khoản này đã tồn tại. Không thể đăng ký đè Passkey!'
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

// 3. API Tạo Challenge Đăng nhập (Ra đề thi)
router.post('/login-options', async (req, res) => {
  const check = validateUsername(req.body.username);
  if (!check.valid) {
    return res.status(400).json({
      error: check.error
    });
  }
  const username = check.username;

  const user = findUserByUsername(username);

  if (!user) {
    return res.status(404).json({
      error: 'Tài khoản không tồn tại!'
    });
  }

  const userCredentials = user.credentials || [];

  if (userCredentials.length === 0) {
    return res.status(400).json({
      error: 'Tài khoản này chưa cài đặt sinh trắc học!'
    });
  }

  try {
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: userCredentials.map(dev => ({
        id: dev.id,
        type: 'public-key',
        transports: dev.transports || [],
      })),
      userVerification: 'preferred',
    });

    req.session.currentChallenge = options.challenge;
    req.session.challengeCreatedAt = Date.now();
    req.session.loginUsername = user.username;

    console.log('==========================================');
    console.log('[ĐĂNG NHẬP] Tạo Challenge thành công');
    console.log('[ĐĂNG NHẬP] Username:', user.username);
    console.log('[ĐĂNG NHẬP] Challenge:', options.challenge);
    console.log('==========================================');

    res.json(options);

  } catch (error) {
    console.error("Lỗi khi tạo challenge đăng nhập:", error);

    return res.status(500).json({
      error: 'Lỗi hệ thống khi khởi tạo đăng nhập.'
    });
  }
});


// 4. API Xác thực Đăng nhập (Chấm điểm)
router.post('/login-verify', async (req, res) => {
  const check = validateUsername(req.body.username);
  if (!check.valid) {
    return res.status(400).json({
      verified: false,
      error: check.error
    });
  }
  const username = check.username;
  const { response } = req.body;

  // PHÒNG CHỐNG CRASH TYPEERROR: Kiểm tra chặt chẽ object response trước khi truy xuất response.id
  if (!response || typeof response !== 'object' || !response.id) {
    return res.status(400).json({
      verified: false,
      error: 'Dữ liệu chữ ký sinh trắc học không hợp lệ hoặc bị thiếu!'
    });
  }

  console.log('==========================================');
  console.log('[ĐĂNG NHẬP] Bắt đầu xác thực');
  console.log('[ĐĂNG NHẬP] Username:', username);
  console.log('[ĐĂNG NHẬP] Credential ID:', response.id);
  console.log('==========================================');

  const user = findUserByUsername(username);

  if (!user) {
    return res.status(404).json({
      error: 'Tài khoản không tồn tại!'
    });
  }

  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({
      error: 'Phiên đăng nhập hết hạn hoặc challenge không hợp lệ. Vui lòng làm lại!'
    });
  }

  // Hủy Challenge ngay lập tức để chống Replay Attack
  req.session.currentChallenge = null;

  const userCredentials = user.credentials || [];

  const currentDevice = userCredentials.find(
    device => device.id === response.id
  );

  if (!currentDevice) {
    return res.status(400).json({
      error: 'Thiết bị này chưa được đăng ký vân tay/FaceID!'
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