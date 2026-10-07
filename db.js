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
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Đường dẫn tới thư mục và file lưu dữ liệu
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'users.json');

// Kho lưu trữ danh sách người dùng trong bộ nhớ RAM
// const users = [];
let users = [];

// ==========================================
// 1. CÁC HÀM ĐỒNG BỘ FILE TỰ ĐỘNG
// ==========================================
// Hàm lưu dữ liệu từ RAM xuống file JSON
function saveUsersToFile() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    // Chuyển mảng users sang chuỗi JSON và ghi đè vào file
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2), 'utf-8');
  } catch (error) {
    console.error('⚠️ [DB] Lỗi khi lưu dữ liệu ra file:', error.message);
  }
}
// Hàm nạp dữ liệu từ file JSON vào RAM khi khởi động
function loadUsersFromFile() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const rawData = fs.readFileSync(DATA_FILE, 'utf-8');
      const parsedUsers = JSON.parse(rawData);
      // 💡 QUAN TRỌNG: Khôi phục lại kiểu Uint8Array cho publicKey
      users = parsedUsers.map(user => ({
        ...user,
        credentials: (user.credentials || []).map(cred => ({
          ...cred,
          publicKey: cred.publicKey ? new Uint8Array(Object.values(cred.publicKey)) : cred.publicKey,
        }))
      }));
      console.log(`📦 [DB] Đã khôi phục thành công ${users.length} tài khoản từ data/users.json`);
    } else {
      console.log('📦 [DB] Chưa có file users.json, khởi tạo kho dữ liệu mới.');
    }
  } catch (error) {
    console.error('⚠️ [DB] Lỗi khi đọc file users.json:', error.message);
    users = [];
  }
}
// Tự động gọi đọc file ngay khi Server bật lên
loadUsersFromFile();


// ==========================================
// 2. CÁC HÀM NGHIỆP VỤ FIDO2 CHUẨN
// ==========================================

/**
 * Hàm tìm kiếm một người dùng trong kho theo tên đăng nhập
 */
export function findUserByUsername(username) {
  return users.find((user) => user.username === username) || null;
}
// 1. export: Từ khóa này rất quan trọng. Nó cho phép các file khác (như file server.js hay file của Người 2) có thể gọi và sử dụng lại hàm này.
// 2. users.find(...): Đây là hàm có sẵn của JavaScript. Nó sẽ rà soát từ đầu đến cuối mảng users để tìm người có user.username trùng khớp với tên được truyền vào.
// 3. || null: Nếu tìm thấy thì trả về thông tin người dùng đó; nếu không tìm thấy ai tên như vậy thì trả về null (nghĩa là rỗng/không tồn tại).


//Hàm tạo một người dùng mới và cất vào kho
export function createUser(username) {
  const newUser = {
    id: `user_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`, // tạo một mã id duy nhất cho người dùng (FIDO2 yêu cầu mỗi tài khoảng phải có id riêng)
    username: username, //tên đăng nhập do người dùng gõ vào (có thể viết ngắn thành: username,)
    credentials: [], // Khởi tạo mảng chìa khoá rỗng (vì người dùng mới dky, chưa quét vân tay nên chưa có khoá)   
  };
  users.push(newUser);
  saveUsersToFile(); // Tự động lưu
  return newUser;
}
// Giải thích từng chi tiết:
// id: user_...: Chuẩn FIDO2 quy định mỗi người dùng phải có một userID duy nhất. Chúng ta dùng thời gian hiện tại (Date.now()) kết hợp chuỗi ngẫu nhiên để đảm bảo không bao giờ có 2 người bị trùng ID.
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
  user.credentials.push(credentialInfo); //nhét chìa khoá mới vào mảng creadentials của người đó
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