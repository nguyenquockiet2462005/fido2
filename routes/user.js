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
    updateUserProfile
} from '../db.js';

const router = express.Router();

const rpID = (process.env.RP_ID || 'localhost').trim();
const origin = (process.env.ORIGIN || 'http://localhost:3000').trim().replace(/\/+$/, '');

const isProduction = process.env.NODE_ENV === 'production';

// BẢO MẬT (CWE-532): Tránh log thông tin nhạy cảm trên production
const debugLog = (...args) => {
    if (!isProduction) console.log(...args);
};


// BẢO MẬT WEBAUTHN (W3C WebAuthn §13.4.1 & OWASP ASVS):
// TRÊN PRODUCTION: CHỈ chấp nhận DUY NHẤT một Origin và một RP ID chính thức để chống Phishing và Relay Attack.
// TRÊN DEVELOPMENT: Cho phép linh hoạt localhost và 127.0.0.1 để tiện kiểm thử cục bộ.
const expectedOrigins = isProduction
    ? [origin]
    : Array.from(new Set([
        origin,
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'https://localhost:3000'
    ]));

const expectedRPIDs = isProduction
    ? [rpID]
    : Array.from(new Set([
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

// ==========================================
// 2. API XÁC THỰC NÂNG CAO (STEP-UP AUTHENTICATION)
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
            userVerification: 'required',
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

        // BẢO MẬT (H3 & Anti XSS): Lọc sạch dữ liệu đầu vào.
        // KHÔNG cho phép sửa studentId qua Step-up để chống giả mạo MSSV.
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
            error: 'Lỗi xác minh sinh trắc học: ' + (err.message || 'Không xác định')
        });
    }
});

export default router;

