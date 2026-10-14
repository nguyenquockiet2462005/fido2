/**
 * public/js/scanner.js - TRÌNH QUÉT THẺ KÉP DUAL-SCAN CAO CẤP (MÃ QR + OCR TIẾNG VIỆT)
 * Tích hợp Auto-Orientation, Pre-warmed Worker và Bộ chuẩn hóa tên Việt Nam thông minh
 */

// Biến lưu trữ Worker AI trong RAM để dùng lại (tăng tốc độ lên dưới 1 giây)
let persistentWorker = null;

/**
 * Hàm khởi tạo hoặc tái sử dụng Worker Tesseract
 */
async function getOcrWorker(progressCallback) {
    if (!persistentWorker) {
        progressCallback("🚀 Đang khởi tạo mô hình AI tiếng Việt...");
        persistentWorker = await window.Tesseract.createWorker('vie', 1, {
            logger: m => {
                if (m.status === 'recognizing text') {
                    const percent = Math.round(m.progress * 100);
                    progressCallback(`🔄 Đang phân tích văn bản thẻ: ${percent}%...`);
                }
            }
        });
    }
    return persistentWorker;
}

/**
 * Hàm làm sạch và tự động chuẩn hóa Họ & Tên tiếng Việt
 * Khử rác mã QR (MM, II, NN) và phục hồi dấu chính tả bị mất
 */
function cleanVietnameseName(rawName) {
    if (!rawName) return "";

    // 1. Tách từng từ
    let words = rawName.trim().split(/\s+/).filter(Boolean);

    // 2. Khử các cụm ký tự rác do dính hoa văn viền thẻ hoặc ô vuông mã QR (như MM, II, NN, LL...)
    const junkTokens = ["MM", "II", "NN", "LL", "XX", "VV", "QQ", "WW", "ZZ", "BB", "TT", "CC", "QR", "MSSV", "SV"];
    words = words.filter((w) => {
        const upper = w.toUpperCase();
        if (junkTokens.includes(upper)) return false;
        // Từ 1-2 ký tự không chứa nguyên âm tiếng Việt thì coi là rác
        if (w.length <= 2 && !/[AEIOUYÁÀẢÃẠĂẮẰẲẴẶÂẤẦẨẪẬÉÈẺẼẸÊẾỀỂỄỆÍÌỈĨỊÓÒỎÕỌÔỐỒỔỖỘƠỚỜỞỠỢÚÙỦŨỤƯỨỪỬỮỰÝỲỶỸỴ]/i.test(w)) {
            return false;
        }
        return true;
    });

    // 3. Chuẩn hóa Họ & Tên đệm kinh điển của Việt Nam
    words = words.map((w, idx) => {
        const upper = w.toUpperCase();
        // Họ Nguyễn (chiếm 40% dân số Việt Nam) - OCR thường quét thiếu dấu thành NGUYÊN hoặc NGUYEN
        if (idx === 0 && (upper === "NGUYÊN" || upper === "NGUYEN" || upper === "NGUYỆN" || upper === "NGUYÈN")) {
            return "NGUYỄN";
        }
        if (idx === 0 && (upper === "ĐÔ" || upper === "DO")) return "ĐỖ";
        if (idx === 0 && upper === "VU") return "VŨ";
        if (idx === 0 && upper === "VO") return "VÕ";
        if (idx === 0 && upper === "DANG") return "ĐẶNG";
        // Tên đệm Văn / Thị
        if (idx > 0 && idx < words.length - 1 && (upper === "VAN" || upper === "VÂN")) return "VĂN";
        if (idx > 0 && idx < words.length - 1 && upper === "THI") return "THỊ";
        return upper;
    });

    return words.join(" ");
}

/**
 * Hàm bóc tách thông tin chữ bằng biểu thức chính quy thông minh
 */
export function parseHutechCardText(rawText) {
    const result = {
        fullName: '',
        dob: '',
        academicYear: '',
        studentId: '',
        faculty: ''
    };

    if (!rawText) return result;

    console.log("📝 [TESSERACT RAW TEXT]:\n", rawText);

    // 1. NGÀY SINH (nhận diện mọi loại dấu ngăn cách: /, -, ., |, :, khoảng trắng)
    const dobMatch = rawText.match(/(?:Ng[aàáảãạ]y\s*sinh|DOB|Sinh\s*ng[aà]y)[:.;\-~=\s]*([0-9]{1,2}[\s\/\-\.|:Il]+[0-9]{1,2}[\s\/\-\.|:Il]+[0-9]{4})\b/i)
        || rawText.match(/\b([0-9]{1,2}[\s\/\-\.|:Il]+[0-9]{1,2}[\s\/\-\.|:Il]+[0-9]{4})\b/)
        || rawText.match(/\b([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{4})\b/);
    if (dobMatch && dobMatch[1]) {
        result.dob = dobMatch[1].replace(/[\s\-\.|:Il]+/g, '/').trim();
    }

    // 2. KHÓA ĐÀO TẠO (dạng 20xx - 20xx với mọi loại gạch nối)
    const yearMatch = rawText.match(/(?:Kh[oóòỏõọ]a)[:.;\-~=\s]*([0-9]{4}\s*[-–—~./\s]+\s*[0-9]{4})/i)
        || rawText.match(/\b(20\d{2}\s*[-–—~./\s]+\s*20\d{2})\b/);
    if (yearMatch && yearMatch[1]) {
        result.academicYear = yearMatch[1].replace(/[-–—~./\s]+/g, " - ").trim();
    }

    // 3. MSSV (từ nhãn MSSV: ... hoặc dãy 10-11 số bắt đầu bằng 2)
    const mssvMatch = rawText.match(/(?:MSSV|Mã\s*SV|Mã\s*số)[:.;\-~=\s]*([0-9]{8,12})/i)
        || rawText.match(/\b(2\d{9,10})\b/);
    if (mssvMatch && mssvMatch[1]) {
        result.studentId = mssvMatch[1].trim();
    }

    // 4. HỌ VÀ TÊN (Thuật toán 3 tầng)
    // Tầng 1: Tìm theo tiền tố "Họ tên", "Họ và tên", "Full name"
    const nameMatch = rawText.match(/(?:H[oọòóỏõọ]\s*(?:v[aàáảãạ]\s*|&\s*)?t[eêéèẻẽẹ]n|Họ\s*và\s*tên|Tên\s*SV)[:.;\-~=\s]+([^\n\r]+)/i);
    if (nameMatch && nameMatch[1]) {
        // Chỉ cắt bỏ các nhãn hệ thống (lưu ý Khóa phải có số kèm theo để tránh cắt nhầm tên Khoa)
        let clean = nameMatch[1]
            .replace(/\s*(?:Ng[aà]y\s*sinh|DOB|MSSV|Mã\s*SV|Kh[oó]a\s*[:\d]|Khoa\s*[:\d]|Giới\s*tính).*$/i, '')
            .replace(/[^a-zA-ZÀ-ỹ\s]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
        clean = cleanVietnameseName(clean);
        const words = clean.split(/\s+/).filter(w => w.length > 1);
        if (words.length >= 2 && words.length <= 6) {
            result.fullName = clean;
        }
    }

    // Tầng 2: Nếu không thấy tiền tố, duyệt tìm dòng chữ in hoa (ALL-CAPS) đại diện cho tên sinh viên
    if (!result.fullName) {
        const ignoreWords = ["HUTECH", "UNIVERSITY", "ĐẠI HỌC", "DAI HOC", "CÔNG NGHỆ", "CONG NGHE",
            "THẺ SINH VIÊN", "THE SINH VIEN", "THẺ", "THE", "KHOA", "KHÓA",
            "NGÀY SINH", "NGAY SINH", "MSSV", "TP.HCM", "TP HCM"];
        const lines = rawText.split(/[\r\n]+/).map(l => l.trim()).filter(Boolean);

        for (const line of lines) {
            let cleanLine = line.replace(/^(?:H[oọòóỏõọ]\s*(?:v[aàáảãạ]\s*)?t[eêéèẻẽẹ]n)[:.;\-~=\s]*/i, '')
                .replace(/\s*(?:Ng[aà]y\s*sinh|DOB|MSSV|Mã\s*SV|Kh[oó]a\s*[:\d]).*$/i, '')
                .replace(/[^a-zA-ZÀ-ỹ\s]/g, ' ')
                .replace(/\s+/g, ' ')
                .trim();
            cleanLine = cleanVietnameseName(cleanLine);
            const upper = cleanLine.toUpperCase();
            const words = cleanLine.split(/\s+/).filter(w => w.length > 1);

            const isUpper = cleanLine === upper || words.filter(w => /^[A-ZÀ-Ỹ]/.test(w)).length >= 2;
            const containsIgnore = ignoreWords.some(ig => upper.includes(ig));

            if (words.length >= 2 && words.length <= 6 && isUpper && !containsIgnore) {
                result.fullName = upper;
                break;
            }
        }
    }

    return result;
}

/**
 * HÀM TIỀN XỬ LÝ ẢNH TRÊN CANVAS CÓ TỰ ĐỘNG XOAY THẺ NẰM NGANG
 */
function preprocessImage(imageFile, maxWidth = 1200) {
    return new Promise((resolve) => {
        const img = new Image();
        const reader = new FileReader();

        reader.onload = (e) => {
            img.onload = () => {
                let width = img.width;
                let height = img.height;

                // Kiểm tra xem ảnh có bị chụp dọc không (thẻ ngang nhưng ảnh dọc)
                const isPortrait = height > width * 1.15;

                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');

                if (isPortrait) {
                    // Tự động xoay 90 độ theo chiều kim đồng hồ để đưa thẻ về chiều ngang chuẩn
                    let targetWidth = height;
                    let targetHeight = width;
                    if (targetWidth > maxWidth) {
                        targetHeight = Math.round((targetHeight * maxWidth) / targetWidth);
                        targetWidth = maxWidth;
                    }
                    canvas.width = targetWidth;
                    canvas.height = targetHeight;

                    ctx.translate(targetWidth / 2, targetHeight / 2);
                    ctx.rotate((90 * Math.PI) / 180);
                    ctx.drawImage(img, -targetHeight / 2, -targetWidth / 2, targetHeight, targetWidth);
                } else {
                    // Ảnh chụp đã nằm ngang sẵn
                    if (width > maxWidth) {
                        height = Math.round((height * maxWidth) / width);
                        width = maxWidth;
                    }
                    canvas.width = width;
                    canvas.height = height;
                    ctx.drawImage(img, 0, 0, width, height);
                }

                // Tăng độ sắc nét nhẹ cho nét chữ
                const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const d = imgData.data;
                const contrast = 1.15;
                for (let i = 0; i < d.length; i += 4) {
                    const gray = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
                    let adj = (gray - 128) * contrast + 128;
                    adj = Math.min(255, Math.max(0, adj));
                    d[i] = adj;
                    d[i + 1] = adj;
                    d[i + 2] = adj;
                }
                ctx.putImageData(imgData, 0, 0);

                canvas.toBlob((blob) => {
                    resolve(blob || imageFile);
                }, 'image/jpeg', 0.95);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(imageFile);
    });
}

/**
 * HÀM DUAL-SCAN SIÊU TỐC: DÙNG WORKER THƯỜNG TRỰC VÀ CHẠY SONG SONG
 */
export async function scanStudentCardDual(imageFile, progressCallback = () => { }) {
    progressCallback("🟡 Đang tối ưu hóa chiều xoay và độ nét ảnh thẻ...");

    // 1. Tự động xoay ngang và nén ảnh
    const optimizedImage = await preprocessImage(imageFile, 1200);

    progressCallback("🟡 Đang phân tích đồng thời Mã QR và Nhận diện chữ tiếng Việt...");

    // 2. Chạy SONG SONG cả 2 tiến trình bằng Promise.all
    const qrTask = (async () => {
        try {
            if (window.Html5Qrcode) {
                const html5QrCode = new window.Html5Qrcode("qr-hidden-reader");
                let qrResult = null;
                // Thử quét QR trên cả ảnh đã xoay ngang lẫn ảnh gốc
                try {
                    qrResult = await html5QrCode.scanFile(optimizedImage, true);
                } catch (_) {
                    qrResult = await html5QrCode.scanFile(imageFile, true);
                }
                if (qrResult && qrResult.trim()) {
                    return qrResult.trim().replace(/[^0-9]/g, '');
                }
            }
        } catch (e) {
            console.warn("Lỗi QR:", e);
            return null;
        }
        return null;
    })();

    const ocrTask = (async () => {
        try {
            const worker = await getOcrWorker(progressCallback);
            const ocrResult = await worker.recognize(optimizedImage);
            const text = ocrResult?.data?.text || '';
            return parseHutechCardText(text);
        } catch (err) {
            console.warn("Lỗi OCR:", err);
            return {};
        }
    })();

    // Đợi cả 2 tác vụ hoàn thành đồng thời
    const [qrStudentId, ocrData] = await Promise.all([qrTask, ocrTask]);

    const finalStudentId = qrStudentId || ocrData.studentId;

    if (!finalStudentId) {
        throw new Error("Không thể nhận diện được Mã số sinh viên (MSSV) từ thẻ. Vui lòng chụp rõ hơn hoặc chụp thẳng góc mã QR!");
    }

    progressCallback("🎉 Hoàn tất trích xuất dữ liệu thẻ sinh viên!");

    return {
        studentId: finalStudentId,
        fullName: ocrData.fullName || '',
        dob: ocrData.dob || '',
        academicYear: ocrData.academicYear || '',
        faculty: '',
        university: 'Đại học Công nghệ Tp.HCM (HUTECH)'
    };
}
