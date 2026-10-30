/**
 * db.js - Cơ chế lưu trữ dữ liệu linh hoạt (Hybrid Persistence: RAM + JSON + MongoDB Atlas)
 *
 * NGUYÊN LÝ HOẠT ĐỘNG:
 * 1. Lưu trữ trong RAM (Cache) để đọc/ghi tốc độ cao theo chuẩn FIDO2.
 * 2. Tự động đồng bộ nguyên tử (Atomic write) ra file `data/users.json` cục bộ (có sao lưu khi file lỗi).
 * 3. Tự động đồng bộ ngầm lên MongoDB Atlas (nếu có `MONGODB_URI`) kèm hàng đợi `pendingCloudSync`.
 * 4. Tự động chuyển đổi khóa công khai (`publicKey`) giữa `Uint8Array` (RAM) và `Base64URL` (Storage).
 */

// Tự động nạp file .env sớm nhất (do ES Module hoist lệnh import trước khi server.js chạy)
if (typeof process.loadEnvFile === 'function') {
  try { process.loadEnvFile(); } catch (_) { }
}

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DB_NAME = 'fido2_db';
const USERS_COLLECTION = 'users';

const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = process.env.USERS_DATA_FILE
  ? path.resolve(process.env.USERS_DATA_FILE)
  : path.join(DATA_DIR, 'users.json');

export const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'admin').trim();
const DEFAULT_UNIVERSITY = 'Đại học Công nghệ Tp.HCM (HUTECH)';

// Kho lưu trữ danh sách người dùng trong bộ nhớ RAM
let users = [];

/**
 * Chuyển đổi Khóa công khai sang chuỗi Base64URL trước khi lưu trữ
 * Giúp lưu gọn khóa nhị phân trên một dòng JSON/BSON duy nhất
 */
export function toBase64UrlKey(pk) {
  if (typeof pk === 'string') return pk;
  if (pk instanceof Uint8Array || Buffer.isBuffer(pk)) {
    return Buffer.from(pk).toString('base64url');
  }
  return pk;
}

/**
 * Chuẩn hóa Khóa công khai thành Uint8Array khi đưa vào RAM
 * Phục vụ trực tiếp cho thư viện @simplewebauthn/server xác thực chữ ký
 */
export function normalizePublicKey(pk) {
  if (pk instanceof Uint8Array) return pk;
  if (typeof pk === 'string') {
    return new Uint8Array(Buffer.from(pk, 'base64url'));
  }
  return pk;
}

/**
 * Chuẩn hóa cấu trúc hồ sơ (profile): giữ nguyên các trường mở rộng sẵn có
 * và điền giá trị mặc định an toàn cho các trường còn thiếu
 */
function buildDefaultProfile(username, existing) {
  const base = existing && typeof existing === 'object' ? existing : {};
  return {
    ...base,
    fullName: base.fullName || username,
    studentId: base.studentId ?? '',
    dob: base.dob ?? '',
    academicYear: base.academicYear ?? '',
    faculty: base.faculty ?? '',
    university: base.university || DEFAULT_UNIVERSITY,
    isVerifiedCard: Boolean(base.isVerifiedCard),
    avatar: base.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(username)}`,
    verifiedAt: base.verifiedAt || base.updatedAt || null,
  };
}

/**
 * Chuẩn hóa một bản ghi người dùng khi nạp từ File JSON hoặc MongoDB Atlas vào RAM
 * BẢO MẬT: Quyền 'admin' được suy ra từ cấu hình máy chủ (ADMIN_USERNAME), không tin dữ liệu lưu trữ
 */
function normalizeUserRecord(rawUser) {
  const user = { ...rawUser };
  delete user._id; // Loại bỏ ObjectId nội bộ của MongoDB

  const cleanUsername = String(user.username).trim();
  const isAdminAccount = cleanUsername.toLowerCase() === ADMIN_USERNAME.toLowerCase();

  return {
    ...user,
    username: cleanUsername,
    role: isAdminAccount ? 'admin' : 'student',
    profile: buildDefaultProfile(cleanUsername, user.profile),
    credentials: Array.isArray(user.credentials)
      ? user.credentials.map(cred => ({
        ...cred,
        publicKey: normalizePublicKey(cred.publicKey),
      }))
      : [],
  };
}

/**
 * Chuẩn hóa danh sách người dùng an toàn: cô lập lỗi từng bản ghi để một bản ghi hỏng
 * không làm mất toàn bộ danh sách người dùng còn lại
 */
function safeNormalizeUsers(rawList, sourceLabel = 'DB') {
  if (!Array.isArray(rawList)) {
    throw new Error(`Dữ liệu từ ${sourceLabel} không phải là mảng JSON hợp lệ.`);
  }
  const validUsers = [];
  for (const item of rawList) {
    try {
      if (!item || typeof item.username !== 'string' || !item.username.trim()) {
        console.warn(`⚠️ [${sourceLabel}] Bỏ qua bản ghi thiếu username hợp lệ.`);
        continue;
      }
      validUsers.push(normalizeUserRecord(item));
    } catch (err) {
      console.warn(`⚠️ [${sourceLabel}] Bỏ qua bản ghi lỗi (${item?.username || 'unknown'}):`, err.message);
    }
  }
  return validUsers;
}

/**
 * Tạo bản sao người dùng với publicKey ở dạng Base64URL trước khi ghi ra đĩa/Cloud
 * (Không làm biến đổi Uint8Array đang giữ trong RAM)
 */
function serializeUserForStorage(user) {
  return {
    ...user,
    credentials: (user.credentials || []).map(c => ({
      ...c,
      publicKey: toBase64UrlKey(c.publicKey),
    })),
  };
}

// ==========================================
// 1. CÁC HÀM ĐỒNG BỘ DỮ LIỆU (DUAL-ENGINE: LOCAL FILE + CLOUD MONGODB)
// ==========================================
let mongoClient = null;
let mongoCollection = null;
let isCloudSyncing = false;
let pendingCloudSync = false;

// Lưu cục bộ xuống file users.json (Atomic write chống hỏng file khi mất điện/crash)
function saveUsersToFileLocal() {
  try {
    const targetDir = path.dirname(DATA_FILE);
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const sanitizedUsers = users.map(serializeUserForStorage);
    const tempFile = path.join(targetDir, `users_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.tmp`);
    fs.writeFileSync(tempFile, JSON.stringify(sanitizedUsers, null, 2), 'utf-8');
    fs.renameSync(tempFile, DATA_FILE);
  } catch (error) {
    console.error('⚠️ [DB-LOCAL] Lỗi khi lưu dữ liệu ra file:', error.message);
  }
}

// Đồng bộ dữ liệu lên MongoDB Atlas (chạy ngầm kèm cờ pendingCloudSync chống bỏ sót thay đổi)
async function syncUsersToCloud() {
  if (!mongoCollection) return;
  if (isCloudSyncing) {
    pendingCloudSync = true;
    return;
  }
  try {
    isCloudSyncing = true;
    const currentIds = users.map(u => u.id);
    await mongoCollection.deleteMany({ id: { $nin: currentIds } });

    if (users.length > 0) {
      const ops = users.map(u => ({
        replaceOne: {
          filter: { id: u.id },
          replacement: serializeUserForStorage(u),
          upsert: true,
        }
      }));
      await mongoCollection.bulkWrite(ops);
    }
  } catch (err) {
    console.error('⚠️ [DB-CLOUD] Lỗi đồng bộ ngầm lên MongoDB Atlas:', err.message);
  } finally {
    isCloudSyncing = false;
    if (pendingCloudSync) {
      pendingCloudSync = false;
      syncUsersToCloud();
    }
  }
}

// Lưu dữ liệu tổng hợp: Vừa lưu local file, vừa đẩy lên Cloud MongoDB
function saveUsersToFile() {
  saveUsersToFileLocal();
  if (mongoCollection) {
    syncUsersToCloud();
  }
}

/**
 * Khởi tạo kết nối MongoDB Atlas (Nếu có biến MONGODB_URI)
 * Giữ dữ liệu bền vững trên Cloud dù server có restart/sleep
 */
export async function initMongoDB() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.log('📦 [DB] Không phát hiện MONGODB_URI. Sử dụng chế độ lưu trữ cục bộ: data/users.json');
    return;
  }

  try {
    console.log('🔄 [DB] Đang kết nối tới MongoDB Atlas...');
    const { MongoClient } = await import('mongodb');
    mongoClient = new MongoClient(uri);
    await mongoClient.connect();
    const db = mongoClient.db(DB_NAME);
    mongoCollection = db.collection(USERS_COLLECTION);
    console.log('🍃 [DB] Kết nối MongoDB Atlas THÀNH CÔNG! Dữ liệu đã được bảo toàn trên Cloud.');

    // Nạp dữ liệu từ Cloud vào RAM
    const cloudCount = await mongoCollection.countDocuments();
    if (cloudCount > 0) {
      const cloudUsers = await mongoCollection.find({}).toArray();
      users = safeNormalizeUsers(cloudUsers, 'DB-CLOUD');
      console.log(`📦 [DB-CLOUD] Đã tải và đồng bộ thành công ${users.length} tài khoản từ MongoDB Atlas vào RAM.`);
      saveUsersToFileLocal(); // Cập nhật lại file local làm bản sao lưu
    } else if (users.length > 0) {
      console.log(`🚀 [DB-CLOUD] Database Cloud đang trống. Tự động đồng bộ ${users.length} tài khoản ban đầu lên MongoDB Atlas...`);
      await syncUsersToCloud();
      console.log('✅ [DB-CLOUD] Đồng bộ ban đầu lên MongoDB Atlas thành công!');
    }
  } catch (err) {
    console.error('⚠️ [DB-CLOUD] Không thể kết nối MongoDB Atlas, tiếp tục dùng local file:', err.message);
  }
}

// Nạp dữ liệu từ file JSON vào RAM khi khởi động
function loadUsersFromFile() {
  if (!fs.existsSync(DATA_FILE)) {
    console.log('📦 [DB] Chưa có file users.json, khởi tạo kho dữ liệu mới.');
    return;
  }

  try {
    const rawData = fs.readFileSync(DATA_FILE, 'utf-8');
    const parsedUsers = JSON.parse(rawData);
    users = safeNormalizeUsers(parsedUsers, 'DB-LOCAL');
    console.log(`📦 [DB] Đã khôi phục và chuẩn hóa thành công ${users.length} tài khoản từ data/users.json`);
  } catch (error) {
    console.error('⚠️ [DB] Lỗi khi đọc file users.json:', error.message);
    try {
      const backupFile = `${DATA_FILE}.corrupt-${Date.now()}`;
      fs.copyFileSync(DATA_FILE, backupFile);
      console.error(`🛡️ [DB] Đã sao lưu file lỗi sang: ${backupFile}`);
    } catch (_) { }
    users = [];
  }
}

/**
 * BẢO MẬT: Khởi tạo tài khoản Admin mặc định (Seed / Biến môi trường)
 * Tránh lỗ hổng 'ai đăng ký trước sẽ thành admin'
 */
export function seedAdminUser() {
  const existingAdmin = users.find(u => u.username.toLowerCase() === ADMIN_USERNAME.toLowerCase());
  if (!existingAdmin) {
    const adminUser = {
      // BẢO MẬT (W3C WebAuthn §5.4.3): 64 random bytes từ CSPRNG (crypto.randomBytes)
      id: crypto.randomBytes(64).toString('base64url'),
      username: ADMIN_USERNAME,
      role: 'admin',
      profile: buildDefaultProfile(ADMIN_USERNAME, {
        fullName: 'Quản trị viên Hệ thống',
        studentId: 'ADMIN-01',
        dob: '01/01/2000',
        academicYear: 'N/A',
        faculty: 'Quản trị Hệ thống',
        isVerifiedCard: true,
        verifiedAt: new Date().toISOString(),
      }),
      credentials: [],
    };
    users.push(adminUser);
    saveUsersToFile();
    console.log(`🛡️ [DB-SEED] Đã tự động khởi tạo tài khoản Admin mặc định: ${ADMIN_USERNAME}`);
  } else if (existingAdmin.role !== 'admin') {
    existingAdmin.role = 'admin';
    saveUsersToFile();
  }
}

// Tự động đọc file và seed admin ngay khi Server khởi động
loadUsersFromFile();
seedAdminUser();


// ==========================================
// 2. CÁC HÀM NGHIỆP VỤ FIDO2 CHUẨN
// ==========================================

/**
 * Tìm kiếm người dùng theo tên đăng nhập (không phân biệt hoa thường)
 */
export function findUserByUsername(username) {
  if (!username || typeof username !== 'string') return null;
  const normalized = username.trim().toLowerCase();
  return users.find(u => u.username.toLowerCase() === normalized) || null;
}

/**
 * Tìm kiếm người dùng dựa trên mã định danh Passkey (Credential ID)
 * Phục vụ luồng đăng nhập nhanh Usernameless (Discoverable Credentials / 1-chạm)
 */
export function findUserByCredentialId(credentialId) {
  if (!credentialId || typeof credentialId !== 'string') return null;
  return users.find(u =>
    (u.credentials || []).some(cred => cred.id === credentialId)
  ) || null;
}

/**
 * Tạo người dùng mới sau khi xác thực sinh trắc học thành công
 * BẢO MẬT (W3C WebAuthn §5.4.3): User handle (id) là 64 random bytes từ CSPRNG, không chứa PII
 */
export function createUser(username, customId = null) {
  if (!username || typeof username !== 'string' || !username.trim()) {
    throw new Error('Tên đăng nhập không hợp lệ!');
  }
  const cleanUsername = username.trim();
  if (findUserByUsername(cleanUsername)) {
    throw new Error(`Tài khoản đã tồn tại: ${cleanUsername}`);
  }

  const newUser = {
    id: customId || crypto.randomBytes(64).toString('base64url'),
    username: cleanUsername,
    role: 'student',
    profile: buildDefaultProfile(cleanUsername),
    credentials: [],
  };
  users.push(newUser);
  saveUsersToFile();
  return newUser;
}

/**
 * Lưu khóa Passkey mới vào tài khoản người dùng (hỗ trợ nhiều thiết bị trên 1 tài khoản)
 */
export function addCredentialToUser(username, credentialInfo) {
  const user = findUserByUsername(username);
  if (!user) {
    throw new Error(`Không tìm thấy người dùng: ${username}`);
  }

  if (!Array.isArray(user.credentials)) {
    user.credentials = [];
  }
  user.credentials.push({
    ...credentialInfo,
    publicKey: normalizePublicKey(credentialInfo.publicKey),
  });
  saveUsersToFile();
  return user;
}

/**
 * Cập nhật bộ đếm chữ ký (Sign Counter) sau mỗi lần xác thực thành công
 * BẢO MẬT FIDO2: Phát hiện hành vi sao chép (clone) khóa phần cứng
 */
export function updateCredentialCounter(username, credentialId, newCounter) {
  const user = findUserByUsername(username);
  if (!user) {
    throw new Error(`Không tìm thấy người dùng: ${username}`);
  }
  const cred = user.credentials.find(c => c.id === credentialId);
  if (!cred) {
    throw new Error(`Không tìm thấy credential với id: ${credentialId}`);
  }
  cred.counter = newCounter;
  saveUsersToFile();
}

/**
 * Lấy danh sách toàn bộ người dùng (trả về bản sao nông của mảng users)
 */
export function getAllUsers() {
  return [...users];
}

/**
 * BẢO MẬT: Cập nhật hồ sơ sinh viên sau khi đã xác thực nâng cao Step-Up FIDO2
 */
export function updateUserProfile(username, updatedData) {
  const user = findUserByUsername(username);
  if (!user) {
    throw new Error(`Không tìm thấy tài khoản: ${username}`);
  }

  const now = new Date().toISOString();
  user.profile = {
    ...user.profile,
    fullName: updatedData.fullName || user.profile?.fullName || user.username,
    studentId: updatedData.studentId !== undefined ? updatedData.studentId : user.profile?.studentId || '',
    dob: updatedData.dob !== undefined ? updatedData.dob : user.profile?.dob || '',
    faculty: updatedData.faculty !== undefined ? updatedData.faculty : user.profile?.faculty || '',
    academicYear: updatedData.academicYear !== undefined ? updatedData.academicYear : user.profile?.academicYear || '',
    university: user.profile?.university || DEFAULT_UNIVERSITY,
    isVerifiedCard: true,
    verifiedAt: user.profile?.verifiedAt || now,
    updatedAt: now,
  };

  saveUsersToFile();
  return user.profile;
}

/**
 * Xóa người dùng theo username (Phục vụ dọn dẹp dữ liệu kiểm thử tự động;
 * không cho phép xóa tài khoản Quản trị viên hệ thống)
 */
export function deleteUser(username) {
  if (!username || typeof username !== 'string') return false;
  const normalized = username.trim().toLowerCase();
  if (normalized === ADMIN_USERNAME.toLowerCase()) {
    return false;
  }
  const initialLength = users.length;
  users = users.filter(u => u.username.toLowerCase() !== normalized);
  if (users.length !== initialLength) {
    saveUsersToFile();
    return true;
  }
  return false;
}