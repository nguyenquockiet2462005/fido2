/**
 * test-issue5.js - Bộ kiểm thử tự động cho Góp ý số 5 (Session Security & Production Readiness)
 * 
 * Kiểm tra đầy đủ 4 vấn đề:
 * 1. Rate Limiting (Chống DoS Challenge - CWE-307)
 * 2. Lưu trữ Session trên MongoDB Atlas qua MongoStore (Chống mất phiên & tràn RAM)
 * 3. Ẩn các API Debug nhạy cảm trên Production (Chống Information Disclosure - CWE-200)
 * 4. Cơ chế Fail-Secure cho biến môi trường SESSION_SECRET (Chống Hardcoded Secret - CWE-798)
 */

import { app } from './server.js';
import http from 'http';
import { fork } from 'child_process';

console.log('====================================================');
console.log('🧪 BẮT ĐẦU KIỂM THỬ GÓP Ý SỐ 5 (SESSION & PRODUCTION)');
console.log('====================================================\n');

async function runTests() {
  const server = http.createServer(app);

  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}`;

  let passedTests = 0;
  const totalTests = 4;

  try {
    // ----------------------------------------------------
    // TEST 1: KIỂM TRA MONGOSTORE ĐÃ KÍCH HOẠT THÀNH CÔNG
    // ----------------------------------------------------
    console.log('▶ [TEST 1/4] Kiểm tra MongoStore (Lưu phiên trên MongoDB Atlas)...');
    const healthRes = await fetch(`${baseUrl}/api/health`);
    const healthData = await healthRes.json();

    if (healthData.sessionStore === 'MongoStore') {
      console.log('  ✅ THÀNH CÔNG: sessionStore = "MongoStore" (Không dùng MemoryStore mặc định).');
      passedTests++;
    } else {
      console.log('  ❌ THẤT BẠI: sessionStore vẫn đang là MemoryStore!');
    }
    console.log('');

    // ----------------------------------------------------
    // TEST 2: KIỂM TRA RATE LIMITING (CHỐNG DOS CHALLENGE)
    // ----------------------------------------------------
    console.log('▶ [TEST 2/4] Kiểm tra Rate Limiting (Gửi 45 request xin Challenge liên tục)...');
    let rateLimitBlocked = false;
    let blockedAt = 0;

    for (let i = 1; i <= 45; i++) {
      const res = await fetch(`${baseUrl}/api/auth/login-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });

      if (res.status === 429) {
        rateLimitBlocked = true;
        blockedAt = i;
        const body = await res.json();
        console.log(`  ✅ THÀNH CÔNG: Request thứ ${i} bị chặn với mã HTTP 429 (Too Many Requests).`);
        console.log(`     Thông báo: "${body.error}"`);
        break;
      }
    }

    if (rateLimitBlocked && blockedAt <= 41) {
      passedTests++;
    } else {
      console.log('  ❌ THẤT BẠI: Không chặn được request sau 40 lần gửi!');
    }
    console.log('');

    // ----------------------------------------------------
    // TEST 3: KIỂM TRA ẨN ROUTE DEBUG TRÊN PRODUCTION (CWE-200)
    // ----------------------------------------------------
    console.log('▶ [TEST 3/4] Kiểm tra bảo vệ Route Debug (/api/session-debug)...');
    // Ở Dev mode hiện tại: phải truy cập được (200)
    const devDebugRes = await fetch(`${baseUrl}/api/session-debug`);
    const devOk = devDebugRes.status === 200;

    // Giả lập Production mode:
    const prodServerProcess = fork('./server.js', [], {
      env: {
        ...process.env,
        NODE_ENV: 'production',
        PORT: String(port + 1)
      },
      silent: true
    });

    let prodOk = false;
    await new Promise(resolve => setTimeout(resolve, 1500)); // Đợi server prod khởi động

    try {
      const prodDebugRes = await fetch(`http://localhost:${port + 1}/api/session-debug`);
      prodOk = prodDebugRes.status === 404;
      if (devOk && prodOk) {
        console.log('  ✅ THÀNH CÔNG:');
        console.log('     - Môi trường Dev: /api/session-debug trả về HTTP 200 (Cho phép nhóm gỡ lỗi).');
        console.log('     - Môi trường Production: /api/session-debug trả về HTTP 404 (Ẩn hoàn toàn với hacker).');
        passedTests++;
      } else {
        console.log(`  ❌ THẤT BẠI: Dev status=${devDebugRes.status}, Prod status=${prodDebugRes.status}`);
      }
    } finally {
      prodServerProcess.kill();
    }
    console.log('');

    // ----------------------------------------------------
    // TEST 4: KIỂM TRA CHÍNH SÁCH FAIL-SECURE CỦA SESSION_SECRET
    // ----------------------------------------------------
    console.log('▶ [TEST 4/4] Kiểm tra chính sách Fail-Secure khi thiếu SESSION_SECRET trên Production...');
    const failSecureProcess = fork('./server.js', [], {
      env: {
        ...process.env,
        NODE_ENV: 'production',
        SESSION_SECRET: '' // Cố tình bỏ trống secret trên Production
      },
      silent: true
    });

    const exitCode = await new Promise(resolve => {
      failSecureProcess.on('exit', code => resolve(code));
    });

    if (exitCode === 1) {
      console.log('  ✅ THÀNH CÔNG: Server lập tức tự tắt (exit code 1) và từ chối chạy khi thiếu SESSION_SECRET.');
      console.log('     Không bao giờ dùng chuỗi hardcode mặc định trên mạng Internet.');
      passedTests++;
    } else {
      console.log(`  ❌ THẤT BẠI: Server vẫn chạy với exit code ${exitCode}!`);
    }
    console.log('');

  } finally {
    server.close();
  }

  console.log('====================================================');
  console.log(`🎉 KẾT QUẢ: ĐẠT ${passedTests}/${totalTests} BÀI KIỂM THỬ BẢO MẬT & HẠ TẦNG!`);
  console.log('====================================================');

  process.exit(passedTests === totalTests ? 0 : 1);
}

runTests();
