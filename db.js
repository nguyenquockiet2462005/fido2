/**
 * db.js - Cơ sở dữ liệu giả lập trong bộ nhớ RAM (In-Memory Database)
 * 
 * TẠI SAO LẠI DÙNG FILE NÀY?
 * - Giúp toàn bộ nhóm không cần cài đặt MySQL hay MongoDB phức tạp.
 * - Dữ liệu được lưu trong mảng JavaScript `users`, tồn tại suốt quá trình Server chạy.
 * - Cung cấp các hàm tìm kiếm và lưu người dùng chuẩn xác theo quy chuẩn FIDO2.
 */

// Mảng lưu danh sách người dùng trong RAM
// Cấu trúc một User chuẩn FIDO2:
// {
//   id: "user-1711234567890",              // Chuỗi ID độc nhất (gắn liền với Passkey)
//   username: "kiet",                       // Tên tài khoản
//   credentials: [                          // Danh sách các khóa Passkey đã đăng ký
//     {
//       id: "base64url-credential-id...",   // Mã định danh của khóa
//       publicKey: Uint8Array([...]),       // KHÓA CÔNG KHAI (Dùng để kiểm tra chữ ký)
//       counter: 0,                         // Bộ đếm số lần xác thực (chống clone khóa)
//       transports: ["internal"]            // Loại thiết bị (internal: vân tay máy tính/điện thoại, usb: YubiKey)
//     }
//   ]
// }
/**
 * db.js - Cơ chế lưu trữ dữ liệu linh hoạt (Hybrid Persistence)
 * 
 * NGUYÊN LÝ HOẠT ĐỘNG:
 * 1. Lưu trữ trong RAM (Cache) để đọc/ghi siêu tốc.
 * 2. Tự động đồng bộ ra file `data/users.json` để không bị mất dữ liệu khi restart server.
 * 3. Bảo vệ kiểu dữ liệu Uint8Array của Khóa công khai (Public Key).
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Đường dẫn tới thư mục và file lưu dữ liệu
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'users.json');

// Kho lưu trữ danh sách người dùng trong bộ nhớ RAM
// const users = [];
let users = [];

/**
 * CHUẨN HÓA KHÓA CÔNG KHAI (FIDO2 Public Key):
 * Đảm bảo luôn trả về đúng kiểu `Uint8Array` (77 bytes cho ES256 / COSE Key).
 * Phòng chống triệt để lỗi `decodedPublicKey.get is not a function` khi đọc từ MongoDB Binary hoặc JSON file.
 */
export function normalizePublicKey(pk) {
  if (!pk) return pk;

  // 1. Đã là Uint8Array hoặc Buffer
  if (pk instanceof Uint8Array || Buffer.isBuffer(pk)) {
    return new Uint8Array(pk);
  }

  // 2. Đối tượng BSON Binary từ MongoDB Atlas
  if (pk._bsontype === 'Binary' || (pk.buffer && (pk.buffer instanceof Uint8Array || Buffer.isBuffer(pk.buffer) || pk.buffer instanceof ArrayBuffer))) {
    return new Uint8Array(pk.buffer);
  }
  if (typeof pk.value === 'function') {
    const val = pk.value(true);
    if (val) return new Uint8Array(val);
  }

  // 3. Chuỗi Base64
  if (typeof pk === 'string') {
    return new Uint8Array(Buffer.from(pk, 'base64'));
  }

  // 4. Mảng thông thường
  if (Array.isArray(pk)) {
    return new Uint8Array(pk);
  }

  // 5. Object được JSON.parse từ Uint8Array: { "0": 165, "1": 1, ... }
  if (typeof pk === 'object') {
    const values = Object.values(pk);
    return new Uint8Array(values);
  }

  return pk;
}

// ==========================================
// 1. CÁC HÀM ĐỒNG BỘ DỮ LIỆU (DUAL-ENGINE: LOCAL FILE + CLOUD MONGODB)
// ==========================================
let mongoClient = null;
let mongoCollection = null;
let isCloudSyncing = false;

// Lưu cục bộ xuống file users.json (Atomic write chống corrupt file)
function saveUsersToFileLocal() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const tempFile = path.join(DATA_DIR, `users_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.tmp`);
    fs.writeFileSync(tempFile, JSON.stringify(users, null, 2), 'utf-8');
    fs.renameSync(tempFile, DATA_FILE);
  } catch (error) {
    console.error('⚠️ [DB-LOCAL] Lỗi khi lưu dữ liệu ra file:', error.message);
  }
}

// Đồng bộ dữ liệu lên MongoDB Atlas (chạy ngầm không gây block request)
async function syncUsersToCloud() {
  if (!mongoCollection || isCloudSyncing) return;
  try {
    isCloudSyncing = true;
    const currentIds = users.map(u => u.id);
    // Xóa những user không còn tồn tại trong RAM (nếu có tài khoản bị hủy)
    await mongoCollection.deleteMany({ id: { $nin: currentIds } });

    if (users.length > 0) {
      const ops = users.map(u => ({
        replaceOne: {
          filter: { id: u.id },
          replacement: {
            ...u,
            credentials: (u.credentials || []).map(c => ({
              ...c,
              publicKey: normalizePublicKey(c.publicKey)
            }))
          },
          upsert: true
        }
      }));
      await mongoCollection.bulkWrite(ops);
    }
  } catch (err) {
    console.error('⚠️ [DB-CLOUD] Lỗi đồng bộ ngầm lên MongoDB Atlas:', err.message);
  } finally {
    isCloudSyncing = false;
  }
}

// Hàm lưu dữ liệu tổng hợp: Vừa lưu local file, vừa đẩy lên Cloud MongoDB
function saveUsersToFile() {
  saveUsersToFileLocal();
  if (mongoCollection) {
    syncUsersToCloud();
  }
}

/**
 * Khởi tạo kết nối MongoDB Atlas (Nếu có biến MONGODB_URI)
 * Giữ dữ liệu vĩnh viễn trên Render dù server có restart/sleep
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
    const db = mongoClient.db('fido2_db');
    mongoCollection = db.collection('users');
    console.log('🍃 [DB] Kết nối MongoDB Atlas THÀNH CÔNG! Dữ liệu đã được bảo toàn trên Cloud.');

    // Nạp dữ liệu từ Cloud vào RAM
    const cloudCount = await mongoCollection.countDocuments();
    if (cloudCount > 0) {
      const cloudUsers = await mongoCollection.find({}).toArray();
      users = cloudUsers.map(user => {
        const { _id, ...rest } = user;
        return {
          ...rest,
          credentials: (rest.credentials || []).map(cred => ({
            ...cred,
            publicKey: normalizePublicKey(cred.publicKey),
          }))
        };
      });
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

// Hàm nạp dữ liệu từ file JSON vào RAM khi khởi động
function loadUsersFromFile() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const rawData = fs.readFileSync(DATA_FILE, 'utf-8');
      const parsedUsers = JSON.parse(rawData);

      // 💡 Migration tự động: Bổ sung role và profile chuẩn nếu tài khoản cũ chưa có
      // CHÚ Ý AN NINH: Chỉ tài khoản 'admin' chính thức mới có quyền admin
      users = parsedUsers.map(user => ({
        ...user,
        role: user.username.toLowerCase() === 'admin' && user.role === 'admin' ? 'admin' : (user.username.toLowerCase() === 'admin' ? 'admin' : 'student'),
        profile: {
          fullName: user.profile?.fullName || user.username,
          studentId: user.profile?.studentId || '',
          dob: user.profile?.dob || '',
          academicYear: user.profile?.academicYear || '',
          faculty: user.profile?.faculty || '',
          university: 'Đại học Công nghệ Tp.HCM (HUTECH)',
          isVerifiedCard: user.profile?.isVerifiedCard || false,
          avatar: user.profile?.avatar || `https://api.dicebear.com/7.x/bottts/svg?seed=${user.username}`,
          verifiedAt: user.profile?.verifiedAt || null
        },
        credentials: (user.credentials || []).map(cred => ({
          ...cred,
          publicKey: normalizePublicKey(cred.publicKey),
        }))
      }));
      console.log(`📦 [DB] Đã khôi phục và chuẩn hóa thành công ${users.length} tài khoản từ data/users.json`);
    } else {
      console.log('📦 [DB] Chưa có file users.json, khởi tạo kho dữ liệu mới.');
    }
  } catch (error) {
    console.error('⚠️ [DB] Lỗi khi đọc file users.json:', error.message);
    users = [];
  }
}

/**
 * BẢO MẬT: Khởi tạo tài khoản Admin mặc định (Seed / Biến môi trường)
 * Tránh lỗ hổng 'ai đăng ký trước sẽ thành admin'
 */
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

export function seedAdminUser() {
  const existingAdmin = users.find(u => u.username.toLowerCase() === ADMIN_USERNAME.toLowerCase());
  if (!existingAdmin) {
    const adminUser = {
      // BẢO MẬT (W3C WebAuthn §5.4.3): 64 random bytes từ CSPRNG (crypto.randomBytes)
      id: crypto.randomBytes(64).toString('base64url'),
      username: ADMIN_USERNAME,
      role: 'admin',
      profile: {
        fullName: 'Quản trị viên Hệ thống',
        studentId: 'ADMIN-01',
        dob: '01/01/2000',
        academicYear: 'N/A',
        faculty: 'Quản trị Hệ thống',
        university: 'Đại học Công nghệ Tp.HCM (HUTECH)',
        isVerifiedCard: true,
        avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${ADMIN_USERNAME}`,
        verifiedAt: new Date().toISOString()
      },
      credentials: []
    };
    users.push(adminUser);
    saveUsersToFile();
    console.log(`🛡️ [DB-SEED] Đã tự động khởi tạo tài khoản Admin mặc định: ${ADMIN_USERNAME}`);
  } else if (existingAdmin.role !== 'admin') {
    existingAdmin.role = 'admin';
    saveUsersToFile();
  }
}

// Tự động gọi đọc file và seed admin ngay khi Server bật lên
loadUsersFromFile();
seedAdminUser();


// ==========================================
// 2. CÁC HÀM NGHIỆP VỤ FIDO2 CHUẨN
// ==========================================

/**
 * Hàm tìm kiếm một người dùng trong kho theo tên đăng nhập
 */
export function findUserByUsername(username) {
  if (!username || typeof username !== 'string') return null;
  const normalized = username.trim().toLowerCase();
  const user = users.find((user) => user.username.toLowerCase() === normalized) || null;
  if (user && Array.isArray(user.credentials)) {
    user.credentials.forEach(cred => {
      cred.publicKey = normalizePublicKey(cred.publicKey);
    });
  }
  return user;
}

/**
 * Tìm kiếm người dùng dựa trên mã định danh Passkey (Credential ID)
 * Phục vụ luồng đăng nhập nhanh Usernameless (Không cần nhập username)
 */
export function findUserByCredentialId(credentialId) {
  if (!credentialId || typeof credentialId !== 'string') return null;
  const user = users.find(user => 
    (user.credentials || []).some(cred => cred.id === credentialId)
  ) || null;
  if (user && Array.isArray(user.credentials)) {
    user.credentials.forEach(cred => {
      cred.publicKey = normalizePublicKey(cred.publicKey);
    });
  }
  return user;
}

// Hàm tạo một người dùng mới và cất vào kho
export function createUser(username, customId = null) {
  const cleanUsername = String(username).trim();
  const newUser = {
    // BẢO MẬT (W3C WebAuthn §5.4.3 & OWASP): 64 byte ngẫu nhiên mật mã (CSPRNG via crypto.randomBytes)
    // Không chứa thông tin định danh cá nhân (PII) như username hay timestamp
    id: customId || crypto.randomBytes(64).toString('base64url'),
    username: cleanUsername,
    // BẢO MẬT: Mọi tài khoản đăng ký qua form công khai LUÔN LUÔN là student
    role: 'student',
    profile: {
      fullName: cleanUsername,
      studentId: '',
      dob: '',
      academicYear: '',
      faculty: '',
      university: 'Đại học Công nghệ Tp.HCM (HUTECH)',
      isVerifiedCard: false,
      avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${cleanUsername}`,
      verifiedAt: null
    },
    credentials: [],
  };
  users.push(newUser);
  saveUsersToFile(); // Tự động lưu
  return newUser;
}

// Giải thích từng chi tiết:
// id: Chuẩn W3C WebAuthn (§5.4.3) quy định user handle (userID) là chuỗi byte mờ đục (opaque) tối đa 64 bytes, khuyến nghị dùng 64 random bytes từ bộ sinh số ngẫu nhiên an toàn mật mã (CSPRNG). Tuyệt đối không chứa thông tin định danh cá nhân (PII) hay timestamp dễ đoán.
// credentials: []: Đây là điểm đặc biệt nhất của Passkey! Tài khoản vừa tạo sẽ không có trường password, chỉ có một mảng rỗng sẵn sàng để đón chìa khóa sau khi người dùng quét vân tay.
// users.push(newUser): Giống như hành động INSERT INTO users trong cơ sở dữ liệu, lưu tài khoản vào bộ nhớ RAM.
//
// * Sau này nó dùng ở đâu trong quy trình FIDO2? *
// Khi người dùng nhập tên kiet và bấm "Đăng ký bằng Passkey":
// Backend kiểm tra bằng hàm findUserByUsername("kiet") (ở Đoạn 2) xem tên đã có chưa.
// Nếu chưa có -> Backend lập tức gọi hàm createUser("kiet") này để sinh ra userID.
// Backend lấy userID đó gói vào gói tin Challenge gửi cho trình duyệt, báo cho máy tính biết: "Hãy tạo một cặp chìa khóa gắn liền với userID này".

// ** Hàm cất chìa khoá passkey vào tài khoản của người dùng **
export function addCredentialToUser(username, credentialInfo) {
  const user = findUserByUsername(username); // tìm người dùng trong kho có tồn tại không
  if (!user) { //nếu không!!
    throw new Error(`Không tìm thấy người dùng: ${username}`);
  } //nếu có

  // Đảm bảo mảng credentials luôn tồn tại trước khi push (phòng ngừa lỗi)
  if (!Array.isArray(user.credentials)) {
    user.credentials = [];
  }
  user.credentials.push({
    ...credentialInfo,
    publicKey: normalizePublicKey(credentialInfo.publicKey)
  }); //nhét chìa khoá mới vào mảng creadentials của người đó
  saveUsersToFile(); // Tự động lưu
  return user;
}

// ** credentialInfo là cái gì? **
// Đây là một gói thông tin chứa:
// - id: Mã số của chìa khóa.
// - publicKey: Khóa công khai (Server cất khóa này lại để những lần đăng nhập sau, bạn quét vân tay gửi chữ ký lên thì Server lấy khóa này ra "soi" xem chữ ký có khớp không).
// - counter: Số đếm số lần sử dụng chìa khóa.
// *** user.credentials.push(credentialInfo): ***
// Một người dùng có thể đăng ký nhiều chìa khóa khác nhau (ví dụ: Chìa khóa TouchID trên MacBook, Chìa khóa Windows Hello trên laptop Dell, hoặc khóa cắm cổng USB YubiKey). Lệnh .push() này cho phép bạn thêm nhiều chìa khóa vào cùng 1 tài khoản!

// *** Sau này nó dùng ở đâu trong quy trình FIDO2? *** 
// Hàm này sẽ được Người 2 (Backend) gọi ở bước cuối cùng của Luồng Đăng ký:

// - Trình duyệt gửi gói tin vân tay vừa quét lên Server.
// - Server dùng thư viện @simplewebauthn/server kiểm tra gói tin hợp lệ.
// - Server gọi ngay: addCredentialToUser("kiet", { id, publicKey, counter }).
// Kể từ lúc này, bạn đã chính thức có một tài khoản được bảo vệ bằng Passkey!


// *** Hàm cập nhật bộ đếm ***
// export function updateCredentialCounter(username, credentialId, newCounter){
//   const user = findUserByUsername(username);
//   if (!user) return;
// // Tìm đúng chiếc chìa khoá vừa dùng để đăng nhập
//   const cred = user.credentials.find((c) => c.id === credentialId);
//   if (cred) {
//     cred.counter = newCounter; //Cập nhật lại số đếm mới (tránh trùng lặp)
//   }
// }

// // *** Hàm lấy toàn bộ danh sách người dùng (dùng để kiểm tra dữ liệu và hiển thị)  

// export function getAllUsers() {
//   return users;
// }

export function updateCredentialCounter(username, credentialId, newCounter) {
  const user = findUserByUsername(username);
  if (!user) {
    throw new Error(`Không tìm thấy người dùng: ${username}`);
  }
  const cred = user.credentials.find((c) => c.id === credentialId);
  if (!cred) {
    throw new Error(`Không tìm thấy credential với id: ${credentialId}`);
  }
  cred.counter = newCounter;
  saveUsersToFile(); // Tự động lưu
}
export function getAllUsers() {
  return [...users]; // Trả về bản sao để bảo vệ mảng gốc
}

// *** Giải thích từng chi tiết:
// Tại sao phải có hàm updateCredentialCounter? (Nguyên lý bảo mật FIDO2)
// Mỗi lần bạn chạm vân tay để đăng nhập, con chip bảo mật trên máy tính sẽ tự động cộng thêm 1 đơn vị vào số đếm (ví dụ từ 1 -> 2 -> 3).
// Khi Server xác minh xong, nó phải cập nhật lại số đếm mới này vào tài khoản.
// Nếu lần sau có ai đó gửi lên chữ ký với số đếm cũ (hoặc nhỏ hơn), Server sẽ biết ngay là có kẻ gian đang cố gắng sao chép chiếc chìa khóa đó!
// Hàm getAllUsers() để làm gì?
// Đơn giản là trả về toàn bộ mảng users.
// Nhóm bạn và Người 4 (UI) có thể gọi hàm này để in danh sách tài khoản ra giao diện web, giúp thầy cô khi chấm bài nhìn thấy tận mắt chiếc chìa khóa (Public Key) vừa được lưu vào RAM như thế nào.

/**
 * Hàm tìm người dùng theo Mã Số Sinh Viên (MSSV)
 */
export function findUserByStudentId(studentId) {
  if (!studentId) return null;
  return users.find(u => u.profile && u.profile.studentId === studentId) || null;
}

/**
 * HÀM CỐT LÕI: Xác thực & Thu hồi quyền sở hữu danh tính khi có Thẻ Vật Lý
 * (Physical Proof Ownership & Identity Reclamation)
 */
export function claimStudentIdentity(currentUsername, cardData) {
  const currentUser = findUserByUsername(currentUsername);
  if (!currentUser) {
    throw new Error(`Không tìm thấy tài khoản: ${currentUsername}`);
  }

  const { studentId, fullName, dob, academicYear, faculty } = cardData;
  if (!studentId) {
    throw new Error('Thiếu mã số sinh viên (MSSV) hợp lệ từ thẻ!');
  }

  // 1. KIỂM TRA AN NINH: Tài khoản này ĐÃ ĐƯỢC XÁC THỰC THẺ trước đó chưa?
  if (currentUser.profile && currentUser.profile.isVerifiedCard && currentUser.profile.studentId) {
    if (currentUser.profile.studentId !== studentId) {
      throw new Error(`Tài khoản này đã được xác thực với MSSV ${currentUser.profile.studentId}. Bạn không thể liên kết thẻ của sinh viên khác!`);
    }
    // Nếu quét lại cùng MSSV -> Cho phép chạy tiếp xuống bước dưới để cập nhật lại thông tin OCR mới nhất!
  }

  let revokedFakeAccount = null;

  // 2. Kiểm tra xem MSSV này đã bị tài khoản nào khác chiếm dụng chưa
  const existingOwner = findUserByStudentId(studentId);

  if (existingOwner && existingOwner.username !== currentUsername) {
    // Trường hợp A: Tài khoản đó ĐÃ XÁC THỰC THẺ TRƯỚC ĐÓ (isVerifiedCard == true)
    if (existingOwner.profile && existingOwner.profile.isVerifiedCard) {
      throw new Error(`Mã số sinh viên ${studentId} đã được kích hoạt bởi tài khoản chính chủ khác (${existingOwner.username})!`);
    }

    // Trường hợp B: Tài khoản mạo danh chưa xác thực -> Thu hồi và xóa bỏ
    revokedFakeAccount = existingOwner.username;
    console.warn(`🚨 [THU HỒI DANH TÍNH] Phát hiện tài khoản mạo danh "${revokedFakeAccount}" chiếm giữ MSSV ${studentId}. Tiến hành xóa bỏ!`);
    users = users.filter(u => u.username !== existingOwner.username);
  }

  // 2b. Kiểm tra xem có tài khoản nào đăng ký Username trùng MSSV này mà chưa xác thực không
  const usernameSquatter = findUserByUsername(studentId);
  if (usernameSquatter && usernameSquatter.username !== currentUsername && (!usernameSquatter.profile || !usernameSquatter.profile.isVerifiedCard)) {
    console.warn(`🚨 [THU HỒI DANH TÍNH] Phát hiện tài khoản chiếm dụng username MSSV "${studentId}". Tiến hành giải phóng!`);
    if (!revokedFakeAccount) revokedFakeAccount = usernameSquatter.username;
    users = users.filter(u => u.username !== usernameSquatter.username);
  }

  // 3. Gán/Cập nhật thông tin thẻ chính chủ cho tài khoản
  currentUser.profile = {
    ...currentUser.profile,
    fullName: fullName || currentUser.profile.fullName || currentUser.username,
    studentId: studentId,
    dob: dob || currentUser.profile.dob || '',
    academicYear: academicYear || currentUser.profile.academicYear || '',
    faculty: faculty || currentUser.profile.faculty || '',
    university: 'Đại học Công nghệ Tp.HCM (HUTECH)',
    isVerifiedCard: true,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${studentId}`,
    verifiedAt: currentUser.profile.verifiedAt || new Date().toISOString()
  };

  saveUsersToFile();

  return {
    success: true,
    profile: currentUser.profile,
    revokedFakeAccount
  };
}

/**
 * Hàm HỦY LIÊN KẾT THẺ SINH VIÊN (Khi người dùng muốn đổi sang thẻ mới)
 */
export function unlinkStudentCard(username) {
  const user = findUserByUsername(username);
  if (!user) {
    throw new Error(`Không tìm thấy tài khoản: ${username}`);
  }

  user.profile = {
    fullName: user.username,
    studentId: '',
    dob: '',
    academicYear: '',
    faculty: '',
    university: 'Đại học Công nghệ Tp.HCM (HUTECH)',
    isVerifiedCard: false,
    avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${user.username}`,
    verifiedAt: null
  };

  saveUsersToFile();
  return user.profile;
}

/**
 * BẢO MẬT: Cập nhật hồ sơ sinh viên sau khi đã xác thực nâng cao Step-Up FIDO2
 */
export function updateUserProfile(username, updatedData) {
  const user = findUserByUsername(username);
  if (!user) {
    throw new Error(`Không tìm thấy tài khoản: ${username}`);
  }

  user.profile = {
    ...user.profile,
    fullName: updatedData.fullName || user.profile?.fullName || user.username,
    studentId: updatedData.studentId !== undefined ? updatedData.studentId : user.profile?.studentId || '',
    dob: updatedData.dob !== undefined ? updatedData.dob : user.profile?.dob || '',
    faculty: updatedData.faculty !== undefined ? updatedData.faculty : user.profile?.faculty || '',
    academicYear: updatedData.academicYear !== undefined ? updatedData.academicYear : user.profile?.academicYear || '',
    university: 'Đại học Công nghệ Tp.HCM (HUTECH)',
    updatedAt: new Date().toISOString()
  };

  saveUsersToFile();
  return user.profile;
}


