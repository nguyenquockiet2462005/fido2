/**
 * routes/user.js - Quản lý Hồ sơ sinh viên & Xác thực thẻ vật lý HUTECH
 * Đã gia cố an ninh, validation MSSV, chống replay attack trong Step-Up Auth
 */
import express from 'express';
import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

import {
    findUserByUsername,
    updateCredentialCounter,
    updateUserProfile,
    claimStudentIdentity,
    unlinkStudentCard
} from '../db.js';

const router = express.Router();

const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:3000';

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

// Helper lọc sạch ký tự nguy hiểm / HTML Injection trong chuỗi
function sanitizeText(str, maxLen = 100) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/[<>]/g, '') // Khử thẻ HTML
        .trim()
        .substring(0, maxLen);
}

// 1. API Lấy thông tin Hồ sơ cá nhân (Profile)
// Endpoint: GET /api/user/profile
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

// 1b. API rút gọn dành cho Workspace Sinh viên
// Endpoint: GET /api/user/me
router.get('/me', (req, res) => {
    if (!req.session.loggedIn || !req.session.username) {
        return res.status(401).json({ error: 'Chưa đăng nhập!' });
    }

    const user = findUserByUsername(req.session.username);
    if (!user) {
        return res.status(404).json({ error: 'Không tìm thấy tài khoản!' });
    }

    return res.json({
        username: user.username,
        role: user.role || 'student',
        hoTen: user.profile?.fullName || user.username,
        ngaySinh: user.profile?.dob || '--/--/----',
        profile: user.profile,
        credentialsCount: (user.credentials || []).length
    });
});

// 2. API Quét thẻ sinh viên vật lý (Physical Proof Claim)
// Endpoint: PUT /api/user/profile/verify-card
router.put('/profile/verify-card', (req, res) => {
    if (!req.session.loggedIn || !req.session.username) {
        return res.status(401).json({
            error: 'Vui lòng đăng nhập trước khi xác thực thẻ!'
        });
    }

    const { studentId, fullName, dob, academicYear, faculty } = req.body;

    if (!studentId || typeof studentId !== 'string' && typeof studentId !== 'number') {
        return res.status(400).json({
            error: 'Không tìm thấy Mã số sinh viên (MSSV) hợp lệ từ thẻ!'
        });
    }

    const cleanMssv = String(studentId).trim();
    if (cleanMssv.length < 6 || cleanMssv.length > 20 || !/^[0-9a-zA-Z]+$/.test(cleanMssv)) {
        return res.status(400).json({
            error: 'Mã số sinh viên (MSSV) không đúng định dạng hợp lệ!'
        });
    }

    try {
        const result = claimStudentIdentity(req.session.username, {
            studentId: cleanMssv,
            fullName: sanitizeText(fullName, 80),
            dob: sanitizeText(dob, 20),
            academicYear: sanitizeText(academicYear, 30),
            faculty: sanitizeText(faculty, 80)
        });

        return res.json({
            success: true,
            message: 'Xác thực thẻ sinh viên HUTECH thành công!',
            profile: result.profile,
            revokedFakeAccount: result.revokedFakeAccount
        });
    } catch (error) {
        return res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

// ==========================================
// 3. API XÁC THỰC NÂNG CAO (STEP-UP AUTHENTICATION)
// Cập nhật thông tin sinh viên nhạy cảm bằng sinh trắc học FIDO2
// ==========================================

// Endpoint: POST /api/user/profile/step-up-options
router.post('/profile/step-up-options', async (req, res) => {
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

        // Ghi nhớ Challenge cho thao tác Step-Up cập nhật hồ sơ
        req.session.stepUpChallenge = options.challenge;
        req.session.stepUpChallengeTime = Date.now();
        return res.json(options);
    } catch (error) {
        console.error('Lỗi tạo challenge Step-Up:', error);
        return res.status(500).json({
            error: 'Lỗi hệ thống khi khởi tạo xác thực sinh trắc học.'
        });
    }
});

// Endpoint: POST /api/user/profile/step-up-update
router.post('/profile/step-up-update', async (req, res) => {
    if (!req.session.loggedIn || !req.session.username) {
        return res.status(401).json({
            error: 'Vui lòng đăng nhập trước khi thực hiện thao tác này!'
        });
    }

    const { response, profileData } = req.body;
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

    const username = req.session.username;
    const user = findUserByUsername(username);
    if (!user) {
        return res.status(404).json({ error: 'Không tìm thấy tài khoản!' });
    }

    const expectedChallenge = req.session.stepUpChallenge;
    const challengeTime = req.session.stepUpChallengeTime;

    // CHỐNG REPLAY ATTACK: Hủy Challenge ngay lập tức sau lần gọi đầu tiên
    req.session.stepUpChallenge = null;
    req.session.stepUpChallengeTime = null;

    if (!expectedChallenge) {
        return res.status(400).json({
            error: 'Phiên xác thực sinh trắc học đã hết hạn hoặc không hợp lệ. Vui lòng thử lại!'
        });
    }

    // Giới hạn thời gian xác thực trong 2 phút
    if (challengeTime && Date.now() - challengeTime > 2 * 60 * 1000) {
        return res.status(400).json({
            error: 'Phiên xác thực sinh trắc học đã quá hạn (2 phút). Vui lòng quét lại!'
        });
    }

    const userCredentials = user.credentials || [];
    const currentDevice = userCredentials.find(dev => dev.id === response.id);

    if (!currentDevice) {
        return res.status(400).json({
            error: 'Khóa sinh trắc học không khớp với tài khoản này!'
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
            requireUserVerification: false,
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

        // Lọc sạch dữ liệu đầu vào (Anti XSS)
        const sanitized = {
            fullName: sanitizeText(profileData.fullName, 100),
            studentId: sanitizeText(profileData.studentId, 20),
            dob: sanitizeText(profileData.dob, 20),
            faculty: sanitizeText(profileData.faculty, 100),
            academicYear: sanitizeText(profileData.academicYear, 50),
        };

        const updatedProfile = updateUserProfile(user.username, sanitized);

        console.log('==========================================');
        console.log('[STEP-UP AUTH] Xác thực thành công cho user:', user.username);
        console.log('[STEP-UP AUTH] Đã cập nhật hồ sơ mới:', sanitized);
        console.log('==========================================');

        return res.json({
            success: true,
            message: 'Xác thực sinh trắc học thành công! Hồ sơ sinh viên đã được cập nhật an toàn.',
            profile: updatedProfile
        });

    } catch (err) {
        console.error('Lỗi xác minh Step-Up:', err);
        return res.status(400).json({
            success: false,
            error: 'Lỗi xác minh sinh trắc học: ' + (err.message || 'Không xác định')
        });
    }
});

// 4. API Tạo Challenge để Hủy liên kết thẻ (Legacy Step-Up)
// Endpoint: POST /api/user/profile/unlink-card-options
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

        req.session.unlinkChallenge = options.challenge;
        req.session.unlinkChallengeTime = Date.now();
        return res.json(options);
    } catch (error) {
        return res.status(500).json({
            error: 'Lỗi hệ thống khi khởi tạo xác thực hủy thẻ.'
        });
    }
});

// 4. API Xác thực sinh trắc học & Hủy liên kết thẻ (Step-Up Auth Verify)
// Endpoint: POST /api/user/profile/unlink-card-verify
router.post('/profile/unlink-card-verify', async (req, res) => {
    if (!req.session.loggedIn || !req.session.username) {
        return res.status(401).json({
            error: 'Vui lòng đăng nhập trước khi thực hiện thao tác này!'
        });
    }

    const { response } = req.body;
    if (!response || typeof response !== 'object' || !response.id) {
        return res.status(400).json({
            success: false,
            error: 'Dữ liệu xác thực sinh trắc học không hợp lệ hoặc bị thiếu!'
        });
    }

    const username = req.session.username;
    const user = findUserByUsername(username);

    if (!user) {
        return res.status(404).json({ error: 'Không tìm thấy tài khoản!' });
    }

    const expectedChallenge = req.session.unlinkChallenge;
    if (!expectedChallenge) {
        return res.status(400).json({
            error: 'Phiên xác thực đã hết hạn hoặc không hợp lệ. Vui lòng thử lại!'
        });
    }

    // Hủy Challenge ngay lập tức để chống Replay Attack
    req.session.unlinkChallenge = null;

    const userCredentials = user.credentials || [];
    const currentDevice = userCredentials.find(dev => dev.id === response.id);

    if (!currentDevice) {
        return res.status(400).json({
            error: 'Khóa bảo mật không khớp với thiết bị đã đăng ký!'
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

        if (!verification.verified) {
            return res.status(400).json({
                success: false,
                error: 'Xác thực sinh trắc học không thành công!'
            });
        }

        updateCredentialCounter(
            user.username,
            currentDevice.id,
            verification.authenticationInfo.newCounter
        );

        const updatedProfile = unlinkStudentCard(user.username);

        return res.json({
            success: true,
            message: 'Xác thực thành công! Đã hủy liên kết thẻ sinh viên.',
            profile: updatedProfile
        });
    } catch (error) {
        return res.status(400).json({
            success: false,
            error: error.message || 'Xác thực hủy thẻ thất bại.'
        });
    }
});

// Chặn phương thức DELETE nếu không qua xác thực
// Endpoint: DELETE /api/user/profile/unlink-card
router.delete('/profile/unlink-card', (req, res) => {
    return res.status(403).json({
        success: false,
        error: 'Hành động nhạy cảm: Yêu cầu xác thực sinh trắc học (Passkey) để hủy liên kết thẻ!'
    });
});

export default router;
