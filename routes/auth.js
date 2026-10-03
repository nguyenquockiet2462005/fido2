/**
 * routes/auth.js - KHÔNG GIAN LÀM VIỆC CỦA THÀNH VIÊN 2 (Backend FIDO2)
 * 
 * ==============================================================================
 * NHIỆM VỤ CỦA THÀNH VIÊN 2:
 * Viết 4 API cốt lõi sử dụng thư viện `@simplewebauthn/server` và các hàm từ `../db.js`
 * ==============================================================================
 * 
 * 1. API ĐĂNG KÝ (REGISTRATION):
 *    - POST /register-options:
 *      + Nhận username từ client.
 *      + Dùng hàm `generateRegistrationOptions()` tạo Challenge.
 *      + Lưu Challenge vào `req.session.currentChallenge`.
 *      + Trả options dạng JSON về cho trình duyệt.
 *    
 *    - POST /register-verify:
 *      + Nhận gói tin vân tay (RegistrationResponseJSON) từ client gửi lên.
 *      + Lấy Challenge từ `req.session.currentChallenge` ra đối chiếu.
 *      + Dùng hàm `verifyRegistrationResponse()` để kiểm tra tính hợp lệ của chữ ký.
 *      + Nếu hợp lệ -> Gọi `addCredentialToUser()` từ db.js để cất chìa khóa vào RAM.
 * 
 * 2. API ĐĂNG NHẬP (AUTHENTICATION):
 *    - POST /login-options:
 *      + Nhận username từ client.
 *      + Lấy danh sách Passkey của user từ db.js.
 *      + Dùng hàm `generateAuthenticationOptions()` tạo Challenge đăng nhập.
 *      + Cất Challenge vào Session và trả về cho client.
 *    
 *    - POST /login-verify:
 *      + Nhận gói tin chữ ký từ client gửi lên.
 *      + Dùng hàm `verifyAuthenticationResponse()` với Public Key đã lưu trong db.js.
 *      + Nếu hợp lệ -> Cập nhật counter bằng `updateCredentialCounter()` và đánh dấu `req.session.loggedIn = true`.
 */

import { Router } from 'express';
// Gợi ý cho Thành viên 2: Kéo các hàm cần thiết từ thư viện @simplewebauthn/server vào đây:
// import {
//   generateRegistrationOptions,
//   verifyRegistrationResponse,
//   generateAuthenticationOptions,
//   verifyAuthenticationResponse,
// } from '@simplewebauthn/server';

// Kéo các hàm làm việc với dữ liệu người dùng từ db.js:
import {
  findUserByUsername,
  createUser,
  addCredentialToUser,
  updateCredentialCounter,
} from '../db.js';

const router = Router();

// TODO: Thành viên 2 sẽ bắt đầu code các API bên dưới:

export default router;
