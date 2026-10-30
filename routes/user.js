/**
 * routes/user.js - Quản lý Hồ sơ sinh viên & Xác thực nâng cao (Step-Up Auth FIDO2)
 */
import express from 'express';
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

import {
  updateCredentialCounter,
  updateUserProfile
} from '../db.js';
import {
  rpID,
  debugLog,
  getExpectedOrigins,
  getExpectedRPIDs,
  isChallengeExpired,
  getSafeErrorMessage,
  hasRegisteredPasskey,
  requireAuth
} from './auth.js';

const router = express.Router();

// Chuẩn hóa chuỗi đầu vào (Defense-in-Depth: loại bỏ ký tự <, > và giới hạn độ dài;
// việc chống XSS chính được thực hiện qua textContent/escapeHtml ở tầng hiển thị)
function sanitizeText(str, maxLen = 100) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/[<>]/g, '')
    .trim()
    .substring(0, maxLen);
}

// 1. API Lấy thông tin Hồ sơ cá nhân (Hỗ trợ đồng thời /profile và /me)
router.get(['/profile', '/me'], requireAuth, (req, res) => {
  const { user } = req;
  return res.json({
    username: user.username,
    role: user.role || 'student',
    hoTen: user.profile?.fullName || user.username,
    ngaySinh: user.profile?.dob || '--/--/----',
    profile: user.profile,
    credentialsCount: (user.credentials || []).length
  });
});

// ==========================================
// 2. API XÁC THỰC NÂNG CAO (STEP-UP AUTHENTICATION)
// Cập nhật thông tin sinh viên nhạy cảm bằng sinh trắc học FIDO2
// ==========================================

// Endpoint: POST /api/user/profile/step-up-options
router.post('/profile/step-up-options', requireAuth, async (req, res) => {
  const { user } = req;

  if (!hasRegisteredPasskey(user)) {
    return res.status(400).json({
      success: false,
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
      userVerification: 'required',
    });

    // Ghi nhớ Challenge cho thao tác Step-Up cập nhật hồ sơ
    req.session.stepUpChallenge = options.challenge;
    req.session.stepUpChallengeTime = Date.now();
    return res.json(options);
  } catch (error) {
    console.error('Lỗi tạo challenge Step-Up:', error);
    return res.status(500).json({
      success: false,
      error: 'Lỗi hệ thống khi khởi tạo xác thực sinh trắc học.'
    });
  }
});

// Endpoint: POST /api/user/profile/step-up-update
router.post('/profile/step-up-update', requireAuth, async (req, res) => {
  const { user } = req;
  const { response, profileData } = req.body ?? {};

  if (!response || typeof response !== 'object' || !response.id) {
    return res.status(400).json({
      success: false,
      error: 'Dữ liệu chữ ký sinh trắc học không hợp lệ!'
    });
  }

  if (!profileData || typeof profileData !== 'object') {
    return res.status(400).json({
      success: false,
      error: 'Dữ liệu hồ sơ cần cập nhật không hợp lệ!'
    });
  }

  const expectedChallenge = req.session.stepUpChallenge;
  const challengeTime = req.session.stepUpChallengeTime;

  // CHỐNG REPLAY ATTACK: Hủy Challenge ngay lập tức sau lần gọi đầu tiên
  req.session.stepUpChallenge = null;
  req.session.stepUpChallengeTime = null;

  // BẢO MẬT: Kiểm tra Challenge tồn tại và thời hạn TTL 2 phút
  if (!expectedChallenge || isChallengeExpired(challengeTime)) {
    return res.status(400).json({
      success: false,
      error: 'Phiên xác thực sinh trắc học đã quá hạn (2 phút) hoặc không hợp lệ. Vui lòng thử lại!'
    });
  }

  const userCredentials = user.credentials || [];
  const currentDevice = userCredentials.find(dev => dev.id === response.id);

  if (!currentDevice) {
    return res.status(400).json({
      success: false,
      error: 'Khóa sinh trắc học không khớp với tài khoản này!'
    });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: getExpectedOrigins(req),
      expectedRPID: getExpectedRPIDs(),
      credential: {
        id: currentDevice.id,
        publicKey: currentDevice.publicKey,
        counter: currentDevice.counter,
        transports: currentDevice.transports || [],
      },
      requireUserVerification: true,
    });

    if (!verification.verified) {
      return res.status(400).json({
        success: false,
        error: 'Chữ ký sinh trắc học không hợp lệ!'
      });
    }

    // Cập nhật bộ đếm (counter) chống replay/clone thiết bị
    if (verification.authenticationInfo?.newCounter !== undefined) {
      updateCredentialCounter(
        user.username,
        currentDevice.id,
        verification.authenticationInfo.newCounter
      );
    }

    // BẢO MẬT (H3): Chuẩn hóa dữ liệu đầu vào, KHÔNG cho phép sửa studentId qua Step-up
    const sanitized = {
      fullName: sanitizeText(profileData.fullName, 100),
      dob: sanitizeText(profileData.dob, 20),
      faculty: sanitizeText(profileData.faculty, 100),
      academicYear: sanitizeText(profileData.academicYear, 50),
    };

    const updatedProfile = updateUserProfile(user.username, sanitized);

    debugLog('==========================================');
    debugLog('[STEP-UP AUTH] Xác thực thành công cho user:', user.username);
    debugLog('==========================================');

    return res.json({
      success: true,
      message: 'Xác thực sinh trắc học thành công! Hồ sơ sinh viên đã được cập nhật an toàn.',
      profile: updatedProfile
    });

  } catch (err) {
    console.error('Lỗi xác minh Step-Up:', err);
    return res.status(400).json({
      success: false,
      error: getSafeErrorMessage(err, 'Lỗi xác minh sinh trắc học.')
    });
  }
});

export default router;
