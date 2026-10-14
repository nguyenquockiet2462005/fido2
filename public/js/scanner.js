/**
 * public/js/scanner.js - TRÌNH QUÉT THẺ KÉP DUAL-SCAN (MÃ QR + OCR TIẾNG VIỆT)
 * Chuyên trách bóc tách thông tin từ Thẻ Sinh Viên HUTECH
 */

/**
 * Hàm bóc tách thông tin chữ bằng biểu thức chính quy (Regex)
 * dựa trên cấu trúc thẻ sinh viên HUTECH
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

    // 1. Tìm Họ và tên (sau chữ "Họ tên:" hoặc "Họ và tên:")
    const nameMatch = rawText.match(/(?:Họ\s*tên|Ho\s*ten|Họ\s*và\s*tên)[:\s]+([^\n\r]+)/i);
    if (nameMatch && nameMatch[1]) {
        // Lọc bỏ ký tự rác, chỉ lấy chữ cái
        result.fullName = nameMatch[1].replace(/[^a-zA-ZÀ-ỹ\s]/g, '').trim().toUpperCase();
    }

    // 2. Tìm Ngày sinh (định dạng DD/MM/YYYY)
    const dobMatch = rawText.match(/\b(\d{1,2}\/\d{1,2}\/\d{4})\b/);
    if (dobMatch && dobMatch[1]) {
        result.dob = dobMatch[1].trim();
    }

    // 3. Tìm Khóa đào tạo (định dạng YYYY - YYYY)
    const yearMatch = rawText.match(/\b(\d{4}\s*[-–]\s*\d{4})\b/);
    if (yearMatch && yearMatch[1]) {
        result.academicYear = yearMatch[1].replace(/\s+/g, ' ').trim();
    }

    // 4. Tìm MSSV dự phòng từ text (nếu mã QR bị mờ)
    const mssvMatch = rawText.match(/(?:MSSV|Mã\s*SV)[:\s]*([0-9]{8,12})/i);
    if (mssvMatch && mssvMatch[1]) {
        result.studentId = mssvMatch[1].trim();
    }

    return result;
}

/**
 * HÀM DUAL-SCAN: Quét song song cả Mã QR và OCR từ hình ảnh thẻ sinh viên
 * @param {File|Blob} imageFile - Tệp ảnh thẻ chụp từ camera hoặc tải lên
 * @param {Function} progressCallback - Hàm cập nhật tiến trình hiển thị ra giao diện
 */
export async function scanStudentCardDual(imageFile, progressCallback = () => { }) {
    progressCallback("🟡 Bước 1/3: Đang phân tích mã QR ở góc thẻ...");

    let qrStudentId = null;

    // 1. Quét mã QR bằng html5-qrcode (lấy MSSV chính xác 100%)
    try {
        if (window.Html5Qrcode) {
            const html5QrCode = new window.Html5Qrcode("qr-hidden-reader");
            const qrResult = await html5QrCode.scanFile(imageFile, true);
            if (qrResult && qrResult.trim()) {
                // Mã QR trên thẻ HUTECH trả về chính là dãy MSSV (VD: 24800612252)
                qrStudentId = qrResult.trim().replace(/[^0-9]/g, '');
                progressCallback(`✅ Bước 1/3: Đã tìm thấy mã QR! MSSV: ${qrStudentId}`);
            }
        }
    } catch (err) {
        progressCallback("⚠️ Không đọc được mã QR, chuyển sang nhận diện chữ OCR...");
    }

    progressCallback("🟡 Bước 2/3: Đang đọc chữ tiếng Việt (OCR Họ tên, Ngày sinh)...");

    // 2. Quét chữ OCR bằng Tesseract.js
    let ocrData = {};
    try {
        if (window.Tesseract) {
            const ocrResult = await window.Tesseract.recognize(
                imageFile,
                'vie+eng', // Hỗ trợ cả tiếng Việt và tiếng Anh
                {
                    logger: m => {
                        if (m.status === 'recognizing text') {
                            const percent = Math.round(m.progress * 100);
                            progressCallback(`🔄 Đang nhận diện văn bản thẻ: ${percent}%...`);
                        }
                    }
                }
            );

            const text = ocrResult?.data?.text || '';
            ocrData = parseHutechCardText(text);
            progressCallback("✅ Bước 2/3: Đã trích xuất thông tin văn bản thành công!");
        }
    } catch (err) {
        console.warn("Lỗi OCR:", err);
        progressCallback("⚠️ OCR gặp lỗi nhỏ, sử dụng thông tin từ mã QR.");
    }

    // 3. Kết hợp kết quả từ cả 2 nguồn (Ưu tiên MSSV từ mã QR vì chính xác 100%)
    const finalStudentId = qrStudentId || ocrData.studentId;

    if (!finalStudentId) {
        throw new Error("Không thể nhận diện được Mã số sinh viên (MSSV) từ thẻ. Vui lòng chụp rõ hơn hoặc chụp thẳng góc mã QR!");
    }

    progressCallback("🎉 Bước 3/3: Hoàn tất trích xuất dữ liệu thẻ sinh viên!");

    return {
        studentId: finalStudentId,
        fullName: ocrData.fullName || '',
        dob: ocrData.dob || '',
        academicYear: ocrData.academicYear || '',
        faculty: '',
        university: ''
    };
}
