/**
 * routes/auth.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 2 (Backend FIDO2)
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
// const rpID = 'localhost';
// const origin = 'http://localhost:3000';
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:3000';



// ==========================================
// GIAI ĐOẠN 1: ĐĂNG KÝ (REGISTRATION)
// ==========================================

// 1. API Tạo Challenge Đăng ký (Ra đề)
router.post('/register-options', async (req, res) => {
  // Khách đến quầy xin đăng ký và đọc tên
  const { username } = req.body;

  // Kiểm tra người dùng có nhập tên hay chưa
  if (!username) {
    return res.status(400).json({
      error: 'Vui lòng nhập tên người dùng!'
    });
  }

  // Tìm hồ sơ trong cơ sở dữ liệu, nếu chưa có thì tạo mới
  let user = findUserByUsername(username);

  if (!user) {
    user = createUser(username);
  }

  try {
    // Gọi chuyên gia ra một bài toán sinh trắc học
    const options = await generateRegistrationOptions({
      rpName,
      rpID,

      // Chuyển chuỗi văn bản (String) sang mảng Byte (Uint8Array)
      userID: new TextEncoder().encode(user.id),
      userName: user.username,
      attestationType: 'none',

      // Loại trừ các chìa khóa đã đăng ký để tránh tạo trùng lặp trên cùng thiết bị
      excludeCredentials: (user.credentials || []).map(cred => ({
        id: cred.id,
        type: 'public-key',
        transports: cred.transports || [],
      })),

      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred'
      },
    });
    // 'discouraged': Không cần quét vân tay/mặt, chỉ cần chạm nhẹ là cho qua.
    // 'preferred': Nếu máy có Touch ID / Windows Hello / Face ID, hãy BẮT BUỘC người dùng quét sinh trắc học. Nếu máy cũ không có thì mới châm chước.
    // 'required' : BẮT BUỘC phải quét vân tay/mặt, không có là báo lỗi.


    // Lưu "Đề thi gốc" vào túi cá nhân (Session)
    req.session.currentChallenge = options.challenge; //Lưu Challenge vào túi phiên
    //(Rất quan trọng: Server phải nhớ chuỗi này trong session để tí nữa đối chiếu xem chữ ký có ký đúng đề bài không, chống Replay Attack)

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
  // Thu "lời giải" từ trình duyệt gửi lên
  const { username, response } = req.body;

  console.log('==========================================');
  console.log('[ĐĂNG KÝ] Bắt đầu xác thực');
  console.log('[ĐĂNG KÝ] Username:', username);
  console.log('[ĐĂNG KÝ] Credential ID:', response?.id);
  console.log('==========================================');

  // Tìm người dùng trong cơ sở dữ liệu
  const user = findUserByUsername(username);

  if (!user) {
    return res.status(404).json({
      error: 'Tài khoản không tồn tại!'
    });
  }

  // Lấy lại Đề thi gốc từ trong túi cá nhân (Session) ra để đối chiếu
  const expectedChallenge = req.session.currentChallenge;

  if (!expectedChallenge) {
    return res.status(400).json({
      error: 'Không tìm thấy bài thi gốc. Vui lòng thử lại!'
    });
  }

  try {
    // Nhờ chuyên gia chấm điểm xem lời giải có khớp không
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    console.log('[ĐĂNG KÝ] Kết quả xác thực:', verification.verified);

    if (!verification.verified) {
      return res.status(400).json({
        verified: false,
        error: 'Xác thực Passkey không thành công!'
      });
    }

    const { registrationInfo } = verification;
    const credential = registrationInfo.credential;

    if (!credential) {
      return res.status(400).json({
        verified: false,
        error: 'Không lấy được thông tin Passkey từ thiết bị!'
      });
    }

    addCredentialToUser(username, {
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports || [],
    });

    console.log('==========================================');
    console.log('[ĐĂNG KÝ] Lưu Passkey thành công!');
    console.log('[ĐĂNG KÝ] Credential ID:', credential.id);
    console.log('==========================================');

    req.session.currentChallenge = null;

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
      error: error.message
    });
  }
});


// ==========================================
// GIAI ĐOẠN 2: ĐĂNG NHẬP (AUTHENTICATION)
// ==========================================

// 3. API Tạo Challenge Đăng nhập (Ra đề thi)
router.post('/login-options', async (req, res) => {
  const { username } = req.body;

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

    console.log('==========================================');
    console.log('[ĐĂNG NHẬP] Tạo Challenge thành công');
    console.log('[ĐĂNG NHẬP] Username:', username);
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
  const { username, response } = req.body;

  console.log('==========================================');
  console.log('[ĐĂNG NHẬP] Bắt đầu xác thực');
  console.log('[ĐĂNG NHẬP] Username:', username);
  console.log('[ĐĂNG NHẬP] Credential ID:', response?.id);
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
      error: 'Phiên đăng nhập hết hạn. Vui lòng làm lại!'
    });
  }

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
      expectedOrigin: origin,
      expectedRPID: rpID,
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
      username,
      currentDevice.id,
      authenticationInfo.newCounter
    );

    req.session.currentChallenge = null;
    req.session.loggedIn = true;
    req.session.username = user.username;

    console.log('==========================================');
    console.log('[ĐĂNG NHẬP] Đăng nhập thành công!');
    console.log('[ĐĂNG NHẬP] User:', user.username);
    console.log('==========================================');

    return res.json({
      verified: true,
      message: 'Đăng nhập thành công! Chào mừng trở lại.'
    });

  } catch (error) {
    console.error('=========================================');
    console.error('[ĐĂNG NHẬP] LỖI XÁC THỰC');
    console.error(error);
    console.error('=========================================');

    return res.status(400).json({
      verified: false,
      error: error.message
    });
  }
});

export default router;