/**
 * routes/auth.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 2 (Backend FIDO2)
 */

import express from 'express';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

// Import đúng các hàm từ file db.js của bạn
import {
  findUserByUsername,
  createUser,
  addCredentialToUser,
  updateCredentialCounter
} from '../db.js';

const router = express.Router();

const rpName = 'FIDO2 Demo Team';
const rpID = 'localhost';
const origin = `http://${rpID}:3000`;

// =========================================================================
// 1. API TRẢ VỀ TÙY CHỌN ĐĂNG KÝ
// =========================================================================
router.post('/register-options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Thiếu username' });

  // Dùng hàm findUserByUsername từ db.js
  let user = findUserByUsername(username);
  if (!user) {
    user = createUser(username);
  }

  try {
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: new Uint8Array(Buffer.from(user.id)),
      userName: user.username,
      authenticatorSelection: { residentKey: 'discouraged' },
      attestationType: 'none',
    });

    req.session.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Lỗi tạo Registration Options:', error);
    res.status(500).json({ error: 'Lỗi server khi tạo Challenge' });
  }
});

// =========================================================================
// 2. API XÁC MINH CHỮ KÝ ĐĂNG KÝ (Lưu Passkey)
// =========================================================================
router.post('/register-verify', async (req, res) => {
  const { username, response } = req.body;
  const expectedChallenge = req.session.currentChallenge;
  const user = findUserByUsername(username);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'Session hết hạn hoặc không tìm thấy User' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      const { credential } = verification.registrationInfo;

      // Tạo gói thông tin chìa khóa khớp với định nghĩa trong db.js
      const credentialInfo = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: credential.transports,
      };

      // Gọi hàm addCredentialToUser từ db.js
      addCredentialToUser(username, credentialInfo);

      req.session.currentChallenge = undefined;
      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false, error: 'Chữ ký không hợp lệ' });
    }
  } catch (error) {
    console.error('Lỗi xác minh Đăng ký:', error);
    res.status(400).json({ verified: false, error: error.message });
  }
});

// =========================================================================
// 3. API TRẢ VỀ TÙY CHỌN ĐĂNG NHẬP
// =========================================================================
router.post('/login-options', async (req, res) => {
  const { username } = req.body;
  const user = findUserByUsername(username);

  // Kiểm tra biến credentials theo cấu trúc db.js
  if (!user || !user.credentials || user.credentials.length === 0) {
    return res.status(404).json({ error: 'Tài khoản chưa đăng ký thiết bị FIDO2 nào' });
  }

  try {
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.credentials.map(dev => ({
        id: dev.id,
        type: 'public-key',
        transports: dev.transports,
      })),
      userVerification: 'preferred',
    });

    req.session.currentChallenge = options.challenge;
    res.json(options);
  } catch (error) {
    console.error('Lỗi tạo Authentication Options:', error);
    res.status(500).json({ error: 'Lỗi server khi tạo Challenge đăng nhập' });
  }
});

// =========================================================================
// 4. API XÁC MINH CHỮ KÝ ĐĂNG NHẬP
// =========================================================================
router.post('/login-verify', async (req, res) => {
  const { username, response } = req.body;
  const expectedChallenge = req.session.currentChallenge;
  const user = findUserByUsername(username);

  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'Session hết hạn hoặc mất kết nối' });
  }

  // Trích xuất đúng chiếc chìa khóa đang được dùng để đăng nhập
  const device = user.credentials.find(c => c.id === response.id);
  if (!device) {
    return res.status(400).json({ error: 'Thiết bị này chưa được đăng ký' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: device.id,
        publicKey: device.publicKey,
        counter: device.counter,
        transports: device.transports,
      },
    });

    if (verification.verified) {
      // Cập nhật counter bằng hàm updateCredentialCounter trong db.js
      updateCredentialCounter(username, device.id, verification.authenticationInfo.newCounter);

      req.session.currentChallenge = undefined;
      req.session.loggedIn = true;
      req.session.username = username;

      res.json({ verified: true });
    } else {
      res.status(400).json({ verified: false, error: 'Xác minh vân tay/khuôn mặt thất bại' });
    }
  } catch (error) {
    console.error('Lỗi xác minh Đăng nhập:', error);
    res.status(400).json({ verified: false, error: error.message });
  }
});

export default router;