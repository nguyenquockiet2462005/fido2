/**
 * reset-db.js - Kịch bản dọn dẹp sạch toàn bộ tài khoản cũ
 * Xóa trắng cả file local data/users.json và Database trên MongoDB Atlas
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_FILE = path.join(__dirname, 'data', 'users.json');
// BẢO MẬT (CWE-798): Không hardcode chuỗi kết nối. Chỉ đọc từ biến môi trường (.env)
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('❌ Thiếu MONGODB_URI. Hãy chạy bằng: npm run reset-db -- --yes (script đã tự nạp .env)');
  process.exit(1);
}

// An toàn: .env local thường trỏ cùng cluster với Render nên lệnh này xóa cả dữ liệu thật
if (!process.argv.includes('--yes')) {
  console.error('⚠️ Lệnh này XÓA TOÀN BỘ tài khoản và phiên trên database đang trỏ tới.');
  console.error('   Nếu chắc chắn, chạy lại với: npm run reset-db -- --yes');
  process.exit(1);
}

async function resetDatabase() {
  console.log('====================================================');
  console.log('🧹 BẮT ĐẦU DỌN DẸP SẠCH CƠ SỞ DỮ LIỆU FIDO2...');
  console.log('====================================================');

  // 1. Dọn dẹp file local data/users.json
  try {
    const DATA_DIR = path.join(__dirname, 'data');
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(DATA_FILE, '[]', 'utf-8');
    console.log('✅ [LOCAL] Đã làm trống hoàn toàn file: data/users.json');
  } catch (err) {
    console.error('⚠️ [LOCAL] Lỗi xóa file users.json:', err.message);
  }

  // 2. Dọn dẹp trên MongoDB Atlas Cloud
  try {
    console.log('🔄 [CLOUD] Đang kết nối tới MongoDB Atlas để xóa tài khoản...');
    const { MongoClient } = await import('mongodb');
    const client = new MongoClient(uri);
    await client.connect();
    const db = client.db('fido2_db');
    const res = await db.collection('users').deleteMany({});
    const resSessions = await db.collection('sessions').deleteMany({});
    console.log(`✅ [CLOUD] Đã xóa thành công ${res.deletedCount} tài khoản và ${resSessions.deletedCount} phiên session trên MongoDB Atlas!`);
    await client.close();
  } catch (err) {
    console.error('⚠️ [CLOUD] Lỗi kết nối MongoDB Atlas:', err.message);
  }

  console.log('====================================================');
  console.log('🎉 ĐÃ XÓA SẠCH TOÀN BỘ TÀI KHOẢN CŨ THÀNH CÔNG!');
  console.log('👉 Bây giờ khi bạn khởi động lại Server (Local hoặc Render):');
  console.log('   Hệ thống sẽ tự động tạo tài khoản "admin" mới tinh ban đầu');
  console.log('   và bạn có thể bắt đầu đăng ký các tài khoản mới sạch sẽ!');
  console.log('====================================================');
}

resetDatabase();
