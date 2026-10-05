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
const rpID = 'localhost';
const origin = 'http://localhost:3000';

// ==========================================
// GIAI ĐOẠN 1: ĐĂNG KÝ (REGISTRATION)
// ==========================================

// 1. API Tạo Challenge Đăng ký (Ra đề)
router.post('/register-options', async (req, res) => {
    // Khách đến quầy xin đăng ký và đọc tên
    const { username } = req.body;

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
            // Chuyển chuỗi văn bản (String) sang mảng Byte (Uint8Array) theo chuẩn FIDO2 mới
            userID: new TextEncoder().encode(user.id),
            userName: user.username,
            attestationType: 'none',
            authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
        });

        // Lưu "Đề thi gốc" vào túi cá nhân (Session) của người dùng đó
        req.session.currentChallenge = options.challenge;

        // Phát đề thi (chuỗi JSON) về cho điện thoại
        res.json(options);
    } catch (error) {
        console.error("Lỗi khi tạo challenge đăng ký:", error);
        return res.status(500).json({ error: 'Lỗi hệ thống khi khởi tạo đăng ký.' });
    }
});

// 2. API Xác thực Đăng ký (Chấm điểm)
router.post('/register-verify', async (req, res) => {
    // Thu "lời giải" từ điện thoại gửi lên
    const { username, response } = req.body;

    const user = findUserByUsername(username);
    if (!user) {
        return res.status(404).json({ error: 'Tài khoản không tồn tại!' });
    }

    // Lấy lại Đề thi gốc từ trong túi cá nhân (Session) ra để đối chiếu
    const expectedChallenge = req.session.currentChallenge;

    // Nếu túi rỗng (Session hết hạn hoặc khách chưa từng xin đề thi), đuổi về
    if (!expectedChallenge) {
        return res.status(400).json({ error: 'Không tìm thấy bài thi gốc. Vui lòng thử lại!' });
    }

    try {
        // Nhờ chuyên gia chấm điểm xem lời giải có khớp không
        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });

        // Nếu xác thực thành công
        if (verification.verified) {
            const { registrationInfo } = verification;

            // Dùng hàm của sếp để cất chìa khóa vào mảng 'credentials' đúng chuẩn trong db.js
            addCredentialToUser(username, registrationInfo);

            // Xóa Đề thi trong túi Session đi để chống Replay Attack (dùng lại mã cũ)
            req.session.currentChallenge = null;

            return res.json({ verified: true, message: 'Đăng ký sinh trắc học thành công!' });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
});


// ==========================================
// GIAI ĐOẠN 2: ĐĂNG NHẬP (AUTHENTICATION)
// ==========================================

// 3. API Tạo Challenge Đăng nhập (Ra đề thi)
router.post('/login-options', async (req, res) => {
    // Khách hàng tới quầy đọc tên
    const { username } = req.body;

    const user = findUserByUsername(username);

    // Kiểm tra sổ sách: Chưa đăng ký thì chặn lại
    if (!user) {
        return res.status(404).json({ error: 'Tài khoản không tồn tại!' });
    }

    // Lấy danh sách khóa từ mảng `credentials` chuẩn của file db.js do sếp viết
    const userCredentials = user.credentials || [];
    if (userCredentials.length === 0) {
        return res.status(400).json({ error: 'Tài khoản này chưa cài đặt sinh trắc học!' });
    }

    try {
        // Gọi chuyên gia ra đề thi dành riêng cho Đăng nhập
        const options = await generateAuthenticationOptions({
            rpID,
            // Ép điện thoại chỉ được dùng đúng cái vân tay đã đăng ký trong mảng credentials
            allowCredentials: userCredentials.map(dev => ({
                id: dev.credentialID,
                type: 'public-key',
            })),
            userVerification: 'preferred',
        });

        // Tiếp tục lưu Đề thi mới vào túi Session của khách
        req.session.currentChallenge = options.challenge;

        // Phát đề thi về cho điện thoại hiển thị bảng quét
        res.json(options);
    } catch (error) {
        console.error("Lỗi khi tạo challenge đăng nhập:", error);
        return res.status(500).json({ error: 'Lỗi hệ thống khi khởi tạo đăng nhập.' });
    }
});

// 4. API Xác thực Đăng nhập (Chấm điểm)
router.post('/login-verify', async (req, res) => {
    // BƯỚC 1: BÁO DANH
    const { username, response } = req.body;

    const user = findUserByUsername(username);
    if (!user) {
        return res.status(404).json({ error: 'Tài khoản không tồn tại!' });
    }

    // BƯỚC 2: CHUẨN BỊ ĐỐI CHẤT
    // Lấy Đề thi gốc từ túi Session ra
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
        return res.status(400).json({ error: 'Phiên đăng nhập hết hạn. Vui lòng làm lại!' });
    }

    // Lấy danh sách khóa từ mảng `credentials` trong db.js
    const userCredentials = user.credentials || [];

    // BƯỚC 3: KIỂM TRA MÃ THIẾT BỊ (Vòng ngoài)
    // Xem ID chiếc chìa khóa khách đang cầm có khớp với cái đã lưu trong mảng credentials không?
    const currentDevice = userCredentials.find(device => device.credentialID === response.id);

    if (!currentDevice) {
        return res.status(400).json({ error: 'Thiết bị này chưa được đăng ký vân tay/FaceID!' });
    }

    // BƯỚC 4: CHẤM ĐIỂM SINH TRẮC HỌC (Vòng trong)
    try {
        const verification = await verifyAuthenticationResponse({
            response, // Lời giải của khách
            expectedChallenge, // Đề thi gốc
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator: currentDevice, // Bản đồ vân tay cũ để đối chiếu
        });

        // BƯỚC 5: ĐÓNG MỘC ĐĂNG NHẬP
        if (verification.verified) {
            const { authenticationInfo } = verification;

            // Cập nhật số đếm bảo mật (Counter) thông qua hàm của sếp trong db.js
            updateCredentialCounter(username, currentDevice.credentialID, authenticationInfo.newCounter);

            // Xóa Đề thi cũ
            req.session.currentChallenge = null;

            // Cấp "chứng minh thư" vào Session để hệ thống biết khách đã vào cửa
            req.session.loggedIn = true;
            req.session.username = user.username;

            return res.json({ verified: true, message: 'Đăng nhập thành công! Chào mừng trở lại.' });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
});

// Xuất khẩu chuẩn ES Module
export default router;