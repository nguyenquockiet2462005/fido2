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
            // theo chuẩn FIDO2 mới
            userID: new TextEncoder().encode(user.id),

            userName: user.username,

            attestationType: 'none',

            authenticatorSelection: {
                residentKey: 'discouraged',
                userVerification: 'preferred'
            },
        });

        // Lưu "Đề thi gốc" vào túi cá nhân (Session)
        // của người dùng đó
        req.session.currentChallenge = options.challenge;

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

    // Lấy lại Đề thi gốc từ trong túi cá nhân (Session)
    // ra để đối chiếu
    const expectedChallenge = req.session.currentChallenge;

    // Nếu túi rỗng (Session hết hạn hoặc khách chưa từng xin đề thi)
    // thì báo lỗi
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

        console.log(
            '[ĐĂNG KÝ] Kết quả xác thực:',
            verification.verified
        );

        // Nếu xác thực không thành công
        if (!verification.verified) {

            return res.status(400).json({
                verified: false,
                error: 'Xác thực Passkey không thành công!'
            });
        }

        // ==========================================
        // LẤY THÔNG TIN CHÌA KHÓA
        // ==========================================

        const { registrationInfo } = verification;

        /*
         * SimpleWebAuthn trả về thông tin credential
         * nằm bên trong registrationInfo.credential
         *
         * credential gồm:
         * - id: Mã định danh của Passkey
         * - publicKey: Khóa công khai
         * - counter: Bộ đếm
         * - transports: Loại thiết bị
         */

        const credential = registrationInfo.credential;

        // Kiểm tra đề phòng trường hợp credential không tồn tại
        if (!credential) {

            return res.status(400).json({
                verified: false,
                error: 'Không lấy được thông tin Passkey từ thiết bị!'
            });
        }

        // ==========================================
        // LƯU CHÌA KHÓA VÀO DB.JS
        // ==========================================

        /*
         * db.js của sếp đang quy định mỗi credential
         * có cấu trúc:
         *
         * {
         *   id,
         *   publicKey,
         *   counter,
         *   transports
         * }
         *
         * Vì vậy KHÔNG lưu nguyên registrationInfo.
         * Chỉ lấy credential bên trong registrationInfo.
         */

        addCredentialToUser(username, {

            // Mã định danh của Passkey
            id: credential.id,

            // Khóa công khai dùng để kiểm tra chữ ký
            publicKey: credential.publicKey,

            // Bộ đếm số lần sử dụng Passkey
            counter: credential.counter,

            // Thông tin loại thiết bị
            transports: credential.transports || [],
        });

        console.log('==========================================');
        console.log('[ĐĂNG KÝ] Lưu Passkey thành công!');
        console.log('[ĐĂNG KÝ] Credential ID:', credential.id);
        console.log('==========================================');

        // Xóa "Đề thi" sau khi đã sử dụng
        // để chống Replay Attack
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

    // Khách hàng tới quầy đọc tên
    const { username } = req.body;

    const user = findUserByUsername(username);

    // Kiểm tra sổ sách: Chưa đăng ký thì chặn lại
    if (!user) {
        return res.status(404).json({
            error: 'Tài khoản không tồn tại!'
        });
    }

    // Lấy danh sách khóa từ mảng `credentials`
    // chuẩn của file db.js
    const userCredentials = user.credentials || [];

    if (userCredentials.length === 0) {
        return res.status(400).json({
            error: 'Tài khoản này chưa cài đặt sinh trắc học!'
        });
    }

    try {

        // Gọi chuyên gia ra đề thi dành riêng cho Đăng nhập
        const options = await generateAuthenticationOptions({

            rpID,

            // Ép điện thoại chỉ được dùng đúng Passkey
            // đã đăng ký trong mảng credentials
            allowCredentials: userCredentials.map(dev => ({

                // QUAN TRỌNG:
                // db.js lưu mã Passkey bằng trường "id"
                id: dev.id,

                type: 'public-key',

                transports: dev.transports || [],
            })),

            userVerification: 'preferred',
        });

        // Tiếp tục lưu Đề thi mới vào túi Session
        req.session.currentChallenge = options.challenge;

        console.log('==========================================');
        console.log('[ĐĂNG NHẬP] Tạo Challenge thành công');
        console.log('[ĐĂNG NHẬP] Username:', username);
        console.log('[ĐĂNG NHẬP] Challenge:', options.challenge);
        console.log('==========================================');

        // Phát đề thi về cho trình duyệt
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

    // BƯỚC 1: BÁO DANH
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


    // BƯỚC 2: CHUẨN BỊ ĐỐI CHẤT

    // Lấy Đề thi gốc từ túi Session ra
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
        return res.status(400).json({
            error: 'Phiên đăng nhập hết hạn. Vui lòng làm lại!'
        });
    }

    // Lấy danh sách khóa từ mảng `credentials` trong db.js
    const userCredentials = user.credentials || [];


    // BƯỚC 3: KIỂM TRA MÃ THIẾT BỊ (Vòng ngoài)

    /*
     * Xem ID chiếc chìa khóa khách đang cầm
     * có khớp với cái đã lưu trong mảng credentials không?
     *
     * QUAN TRỌNG:
     * db.js dùng trường "id", không phải "credentialID".
     */

    const currentDevice = userCredentials.find(
        device => device.id === response.id
    );

    if (!currentDevice) {

        return res.status(400).json({
            error: 'Thiết bị này chưa được đăng ký vân tay/FaceID!'
        });
    }


    // BƯỚC 4: CHẤM ĐIỂM SINH TRẮC HỌC (Vòng trong)

    try {

        /*
         * SimpleWebAuthn phiên bản mới dùng "credential"
         * thay cho "authenticator".
         *
         * db.js của nhóm đang lưu:
         * id
         * publicKey
         * counter
         * transports
         *
         * nên truyền trực tiếp cấu trúc này vào credential.
         */

        const verification = await verifyAuthenticationResponse({

            // Lời giải của khách
            response,

            // Đề thi gốc
            expectedChallenge,

            // Địa chỉ website được phép xác thực
            expectedOrigin: origin,

            // RP ID của hệ thống
            expectedRPID: rpID,

            // Chìa khóa công khai đã lưu trong DB
            credential: {

                // Mã Passkey
                id: currentDevice.id,

                // Khóa công khai
                publicKey: currentDevice.publicKey,

                // Bộ đếm
                counter: currentDevice.counter,

                // Loại thiết bị
                transports: currentDevice.transports || [],
            },
        });

        console.log(
            '[ĐĂNG NHẬP] Kết quả xác thực:',
            verification.verified
        );


        // BƯỚC 5: ĐÓNG MỘC ĐĂNG NHẬP

        if (!verification.verified) {

            return res.status(400).json({
                verified: false,
                error: 'Xác thực đăng nhập thất bại!'
            });
        }

        const { authenticationInfo } = verification;

        // Cập nhật số đếm bảo mật (Counter)
        // thông qua hàm của sếp trong db.js
        updateCredentialCounter(
            username,
            currentDevice.id,
            authenticationInfo.newCounter
        );

        // Xóa Đề thi cũ
        req.session.currentChallenge = null;

        // Cấp "chứng minh thư" vào Session
        // để hệ thống biết khách đã vào cửa
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

        console.error('==========================================');
        console.error('[ĐĂNG NHẬP] LỖI XÁC THỰC');
        console.error(error);
        console.error('==========================================');

        return res.status(400).json({
            verified: false,
            error: error.message
        });
    }
});


// Xuất khẩu chuẩn ES Module
export default router;