// THAY ĐỔI 1: Sếp dùng cú pháp 'import' (ES Module) đời mới thay vì 'require' cũ
import express from 'express';

// Lôi các chuyên gia FIDO2 từ thư viện ra
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

// Tạo một trạm phân luồng (Router)
const router = express.Router();

// Tạm thời giữ 2 két sắt này để test.
const users = {};
const devices = {};

// Cấu hình định danh cho máy chủ
const rpName = 'FIDO2 Demo';
const rpID = 'localhost';
// THAY ĐỔI 2: Sếp chạy chung giao diện và server ở cổng 3000, nên phải đổi origin thành 3000
const origin = `http://localhost:3000`;


// ==========================================
// GIAI ĐOẠN 1: ĐĂNG KÝ (REGISTRATION)
// ==========================================

// 1. API Tạo Challenge Đăng ký (Ra đề)
router.post('/generate-registration-options', async (req, res) => {
    // Khách đến quầy xin đăng ký và đọc tên
    const { username } = req.body;

    // Nếu tên này chưa có trong sổ, tạo hồ sơ mới
    if (!users[username]) {
        users[username] = { id: username, username };
    }
    const user = users[username];

    // Gọi chuyên gia ra một bài toán sinh trắc học
    const options = await generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        attestationType: 'none',
        authenticatorSelection: { residentKey: 'discouraged', userVerification: 'preferred' },
    });

    // THAY ĐỔI 3: THEO LỆNH SẾP - LƯU CHALLENGE VÀO SESSION
    // Thay vì dùng két sắt chung 'challenges' như trước, sếp bắt lưu "Đề thi gốc" 
    // vào ngay cái túi cá nhân (Session) của người dùng đó.
    req.session.currentChallenge = options.challenge;

    // Phát đề thi (chuỗi JSON) về cho điện thoại
    res.json(options);
});

// 2. API Xác thực Đăng ký (Chấm điểm)
router.post('/verify-registration', async (req, res) => {
    // Thu "lời giải" từ điện thoại gửi lên
    const { username, response } = req.body;
    const user = users[username];

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

            // Lưu bản đồ vân tay/FaceID vào két sắt
            if (!devices[user.id]) {
                devices[user.id] = [];
            }
            devices[user.id].push(registrationInfo);

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
router.post('/generate-authentication-options', async (req, res) => {
    // Khách hàng tới quầy đọc tên
    const { username } = req.body;
    const user = users[username];

    // Kiểm tra sổ sách: Chưa đăng ký thì chặn lại
    if (!user) {
        return res.status(404).json({ error: 'Tài khoản không tồn tại!' });
    }

    // Mở két sắt xem khách này đã cài FaceID/Vân tay nào chưa
    const userDevices = devices[user.id];
    if (!userDevices || userDevices.length === 0) {
        return res.status(400).json({ error: 'Tài khoản này chưa cài đặt sinh trắc học!' });
    }

    // Gọi chuyên gia ra đề thi dành riêng cho Đăng nhập
    const options = await generateAuthenticationOptions({
        rpID,
        // Ép điện thoại chỉ được dùng đúng cái vân tay đã đăng ký hôm trước
        allowCredentials: userDevices.map(dev => ({
            id: dev.credentialID,
            type: 'public-key',
        })),
        userVerification: 'preferred',
    });

    // Tiếp tục lưu Đề thi mới vào túi Session của khách
    req.session.currentChallenge = options.challenge;

    // Phát đề thi về cho điện thoại hiển thị bảng quét
    res.json(options);
});

// 4. API Xác thực Đăng nhập (Chấm điểm)
router.post('/verify-authentication', async (req, res) => {
    // BƯỚC 1: BÁO DANH
    const { username, response } = req.body;
    const user = users[username];

    if (!user) {
        return res.status(404).json({ error: 'Tài khoản không tồn tại!' });
    }

    // BƯỚC 2: CHUẨN BỊ ĐỐI CHẤT
    // Lấy Đề thi gốc từ túi Session ra
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
        return res.status(400).json({ error: 'Phiên đăng nhập hết hạn. Vui lòng làm lại!' });
    }

    // Lấy danh sách vân tay cũ trong két sắt ra
    const userDevices = devices[user.id];

    // BƯỚC 3: KIỂM TRA MÃ THIẾT BỊ (Vòng ngoài)
    // Xem cái điện thoại khách đang cầm có đúng là đồ chính chủ không?
    const currentDevice = userDevices.find(device => device.credentialID === response.id);

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
            // Xóa Đề thi cũ
            req.session.currentChallenge = null;

            // THAY ĐỔI 4: ĐÓNG DẤU SESSION CHO SẾP
            // Sếp có viết 1 cái API là /api/session-debug. 
            // Để sếp biết ông khách này đã vào thành công, ta phải cấp "chứng minh thư" vào Session.
            req.session.loggedIn = true;
            req.session.username = user.username;

            return res.json({ verified: true, message: 'Đăng nhập thành công! Chào mừng trở lại.' });
        }
    } catch (error) {
        return res.status(400).json({ error: error.message });
    }
});

// THAY ĐỔI 5: Cú pháp xuất khẩu trạm phân luồng ra ngoài của ES Module
export default router;