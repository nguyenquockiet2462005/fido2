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
  claimStudentIdentity,
  unlinkStudentCard,
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

  // NẾU ĐÃ CÓ TÀI KHOẢN VÀ ĐÃ CÓ PASSKEY -> CHẶN KHÔNG CHO ĐĂNG KÝ TIẾP
  if (user && user.credentials && user.credentials.length > 0) {
    return res.status(400).json({
      error: 'Tên tài khoản này đã được đăng ký! Vui lòng chọn tên khác hoặc bấm Đăng nhập.'
    });
  }

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

// ==========================================
// GIAI ĐOẠN 3: HỒ SƠ SINH VIÊN & XÁC THỰC THẺ VẬT LÝ
// ==========================================

// 5. API Lấy thông tin Hồ sơ cá nhân (Profile) của phiên hiện tại
router.get('/profile', (req, res) => {
  if (!req.session.loggedIn || !req.session.username) {
    return res.status(401).json({
      error: 'Vui lòng đăng nhập để xem thông tin hồ sơ!'
    });
  }

  const user = findUserByUsername(req.session.username);
  if (!user) {
    return res.status(404).json({
      error: 'Không tìm thấy thông tin tài khoản!'
    });
  }

  return res.json({
    username: user.username,
    role: user.role || 'student',
    profile: user.profile,
    credentialsCount: (user.credentials || []).length
  });
});

// 6. API Xác thực thẻ sinh viên & Thu hồi tài khoản mạo danh (Physical Proof Claim)
router.put('/profile/verify-card', (req, res) => {
  if (!req.session.loggedIn || !req.session.username) {
    return res.status(401).json({
      error: 'Vui lòng đăng nhập trước khi xác thực thẻ!'
    });
  }

  const { studentId, fullName, dob, academicYear, faculty } = req.body;

  if (!studentId) {
    return res.status(400).json({
      error: 'Không tìm thấy Mã số sinh viên (MSSV) hợp lệ từ thẻ!'
    });
  }

  try {
    // Gọi hàm nghiệp vụ cốt lõi đã viết ở Bước 1
    const result = claimStudentIdentity(req.session.username, {
      studentId: String(studentId).trim(),
      fullName: fullName ? String(fullName).trim() : '',
      dob: dob ? String(dob).trim() : '',
      academicYear: academicYear ? String(academicYear).trim() : '',
      faculty: faculty ? String(faculty).trim() : ''
    });

    console.log('==========================================');
    console.log('[XÁC THỰC THẺ] Thành công cho user:', req.session.username);
    console.log('[XÁC THỰC THẺ] MSSV:', studentId);
    if (result.revokedFakeAccount) {
      console.log(`[THU HỒI] Đã xóa tài khoản mạo danh: ${result.revokedFakeAccount}`);
    }
    console.log('==========================================');

    return res.json({
      success: true,
      message: 'Xác thực thẻ sinh viên HUTECH thành công!',
      profile: result.profile,
      revokedFakeAccount: result.revokedFakeAccount
    });
  } catch (error) {
    console.error('❌ [LỖI XÁC THỰC THẺ]:', error.message);
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// 7. API Tạo Challenge Xác thực Sinh trắc học để Hủy liên kết thẻ (Step-Up Auth Options)
router.post('/profile/unlink-card-options', async (req, res) => {
  if (!req.session.loggedIn || !req.session.username) {
    return res.status(401).json({
      error: 'Vui lòng đăng nhập trước khi thực hiện thao tác này!'
    });
  }

  const username = req.session.username;
  const user = findUserByUsername(username);

  if (!user || !user.credentials || user.credentials.length === 0) {
    return res.status(400).json({
      error: 'Tài khoản chưa có Passkey sinh trắc học để xác thực!'
    });
  }

  try {
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.credentials.map(dev => ({
        id: dev.id,
        type: 'public-key',
        transports: dev.transports || [],
      })),
      userVerification: 'preferred',
    });

    // Lưu challenge riêng biệt cho phiên hủy thẻ
    req.session.unlinkChallenge = options.challenge;

    console.log('==========================================');
    console.log('[HỦY THẺ - BẢO MẬT] Tạo Challenge xác thực');
    console.log('[HỦY THẺ] Username:', username);
    console.log('[HỦY THẺ] Challenge:', options.challenge);
    console.log('==========================================');

    return res.json(options);
  } catch (error) {
    console.error('❌ [LỖI TẠO CHALLENGE HỦY THẺ]:', error);
    return res.status(500).json({
      error: 'Lỗi hệ thống khi khởi tạo xác thực hủy thẻ.'
    });
  }
});

// 8. API Xác thực Chữ ký Passkey & Hủy liên kết thẻ (Step-Up Auth Verify)
router.post('/profile/unlink-card-verify', async (req, res) => {
  if (!req.session.loggedIn || !req.session.username) {
    return res.status(401).json({
      error: 'Vui lòng đăng nhập trước khi thực hiện thao tác này!'
    });
  }

  const { response } = req.body;
  const username = req.session.username;
  const user = findUserByUsername(username);

  if (!user) {
    return res.status(404).json({
      error: 'Không tìm thấy tài khoản!'
    });
  }

  const expectedChallenge = req.session.unlinkChallenge;
  if (!expectedChallenge) {
    return res.status(400).json({
      error: 'Phiên xác thực đã hết hạn hoặc không hợp lệ. Vui lòng thử lại!'
    });
  }

  const userCredentials = user.credentials || [];
  const currentDevice = userCredentials.find(
    dev => dev.id === response?.id
  );

  if (!currentDevice) {
    return res.status(400).json({
      error: 'Khóa bảo mật không khớp với thiết bị đã đăng ký!'
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

    console.log('[HỦY THẺ] Kết quả xác thực Passkey:', verification.verified);

    if (!verification.verified) {
      return res.status(400).json({
        success: false,
        error: 'Xác thực sinh trắc học không thành công!'
      });
    }

    // Cập nhật counter chống tấn công phát lại (Replay attack)
    const { authenticationInfo } = verification;
    updateCredentialCounter(
      username,
      currentDevice.id,
      authenticationInfo.newCounter
    );

    // Xóa challenge sau khi dùng
    req.session.unlinkChallenge = null;

    // Tiến hành hủy liên kết thẻ sinh viên trong database
    const updatedProfile = unlinkStudentCard(username);
    console.log(`[HỦY THẺ] ✅ Xác thực thành công! Tài khoản "${username}" đã hủy liên kết thẻ sinh viên.`);

    return res.json({
      success: true,
      message: 'Xác thực thành công! Đã hủy liên kết thẻ sinh viên.',
      profile: updatedProfile
    });

  } catch (error) {
    console.error('❌ [LỖI XÁC THỰC HỦY THẺ]:', error);
    return res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// Chặn phương thức DELETE trực tiếp nếu không qua xác thực
router.delete('/profile/unlink-card', (req, res) => {
  return res.status(403).json({
    success: false,
    error: 'Hành động nhạy cảm: Yêu cầu xác thực sinh trắc học (Passkey) để hủy liên kết thẻ!'
  });
});



export default router;