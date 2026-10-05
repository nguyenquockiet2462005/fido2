package com.mycompany.gui_fido2;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

public class FIDO2_ECC {

    private KeyPair keyPair;
    private boolean isRegistered = false;

    // 1. Đăng ký token FIDO2 (Sinh cặp khóa ECC P-256)
    public void registerFIDO2Token() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
        keyPairGen.initialize(256);
        this.keyPair = keyPairGen.generateKeyPair();
        this.isRegistered = true;
    }

    // Lấy chuỗi Public Key dưới dạng Base64 để gửi lên Server
    public String getPublicKeyBase64() {
        if (keyPair == null) return "";
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    // Kiểm tra thiết bị đã đăng ký chưa
    public boolean isRegistered() {
        return isRegistered;
    }

    // 2. Server phát sinh chuỗi Challenge ngẫu nhiên (32 bytes Base64)
    public String generateServerChallenge() {
        byte[] challengeBytes = new byte[32];
        new SecureRandom().nextBytes(challengeBytes);
        return Base64.getEncoder().encodeToString(challengeBytes);
    }

    // 3. Thiết bị FIDO2 dùng Private Key để ký lên Challenge
    public String signChallenge(String challenge) throws Exception {
        if (keyPair == null) {
            throw new IllegalStateException("Cặp khóa ECC chưa được khởi tạo!");
        }
        Signature ecdsaSign = Signature.getInstance("SHA256withECDSA");
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(challenge.getBytes(StandardCharsets.UTF_8));
        byte[] signature = ecdsaSign.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // 4. Server dùng Public Key để kiểm tra chữ ký số từ Challenge
    public boolean verifyAssertion(String challenge, String signatureBase64) throws Exception {
        if (keyPair == null) return false;
        
        Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(keyPair.getPublic());
        ecdsaVerify.update(challenge.getBytes(StandardCharsets.UTF_8));
        
        byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
        return ecdsaVerify.verify(signatureBytes);
    }
}
