/**
 * routes/user.js - Quản lý Hồ sơ sinh viên & Xác thực thẻ vật lý HUTECH
 */
import express from 'express';
import {
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from '@simplewebauthn/server';

import {
    findUserByUsername,
    updateCredentialCounter,
    claimStudentIdentity,
    unlinkStudentCard
} from '../db.js';

const router = express.Router();

const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:3000';

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

    if (!studentId) {
        return res.status(400).json({
            error: 'Không tìm thấy Mã số sinh viên (MSSV) hợp lệ từ thẻ!'
        });
    }

    try {
        const result = claimStudentIdentity(req.session.username, {
            studentId: String(studentId).trim(),
            fullName: fullName ? String(fullName).trim() : '',
            dob: dob ? String(dob).trim() : '',
            academicYear: academicYear ? String(academicYear).trim() : '',
            faculty: faculty ? String(faculty).trim() : ''
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

// 3. API Tạo Challenge để Hủy liên kết thẻ (Step-Up Auth Options)
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

    const userCredentials = user.credentials || [];
    const currentDevice = userCredentials.find(dev => dev.id === response?.id);

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

        if (!verification.verified) {
            return res.status(400).json({
                success: false,
                error: 'Xác thực sinh trắc học không thành công!'
            });
        }

        updateCredentialCounter(
            username,
            currentDevice.id,
            verification.authenticationInfo.newCounter
        );

        req.session.unlinkChallenge = null;
        const updatedProfile = unlinkStudentCard(username);

        return res.json({
            success: true,
            message: 'Xác thực thành công! Đã hủy liên kết thẻ sinh viên.',
            profile: updatedProfile
        });
    } catch (error) {
        return res.status(400).json({
            success: false,
            error: error.message
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
