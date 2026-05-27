package com.siruoren.encrypted_management;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * CredentialBackupService 单元测试
 * 测试公开的加密/解密API（encryptData/decryptData）
 */
@DisplayName("CredentialBackupService 单元测试")
public class CredentialBackupServiceTest {

    private static final String TEST_PASSWORD = "testPassword123!";
    private static final String TEST_PLAINTEXT = "{\"test\": \"data\", \"number\": 123}";

    @Test
    @DisplayName("AES-256-GCM 加密解密测试")
    public void testEncryptionDecryption() throws Exception {
        String encrypted = CredentialBackupService.encryptData(TEST_PLAINTEXT, TEST_PASSWORD);
        assertNotNull(encrypted);
        assertFalse(encrypted.isEmpty());

        String decrypted = CredentialBackupService.decryptData(encrypted, TEST_PASSWORD);
        assertEquals(TEST_PLAINTEXT, decrypted);
    }

    @Test
    @DisplayName("错误密码解密应该失败")
    public void testDecryptWithWrongPassword() {
        assertThrows(Exception.class, () -> {
            String encrypted = CredentialBackupService.encryptData(TEST_PLAINTEXT, TEST_PASSWORD);
            CredentialBackupService.decryptData(encrypted, "wrongPassword123!");
        });
    }

    @Test
    @DisplayName("空密码解密应该失败")
    public void testDecryptWithEmptyPassword() {
        assertThrows(Exception.class, () -> {
            String encrypted = CredentialBackupService.encryptData(TEST_PLAINTEXT, TEST_PASSWORD);
            CredentialBackupService.decryptData(encrypted, "");
        });
    }

    @Test
    @DisplayName("空数据加密解密测试")
    public void testEmptyDataEncryption() throws Exception {
        String encrypted = CredentialBackupService.encryptData("", TEST_PASSWORD);
        assertNotNull(encrypted);

        String decrypted = CredentialBackupService.decryptData(encrypted, TEST_PASSWORD);
        assertEquals("", decrypted);
    }

    @Test
    @DisplayName("特殊字符加密解密测试")
    public void testSpecialCharactersEncryption() throws Exception {
        String specialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?\\~`";
        String encrypted = CredentialBackupService.encryptData(specialChars, TEST_PASSWORD);
        String decrypted = CredentialBackupService.decryptData(encrypted, TEST_PASSWORD);
        assertEquals(specialChars, decrypted);
    }

    @Test
    @DisplayName("中文字符加密解密测试")
    public void testChineseCharactersEncryption() throws Exception {
        String chineseText = "测试中文内容 凭据管理";
        String encrypted = CredentialBackupService.encryptData(chineseText, TEST_PASSWORD);
        String decrypted = CredentialBackupService.decryptData(encrypted, TEST_PASSWORD);
        assertEquals(chineseText, decrypted);
    }

    @Test
    @DisplayName("长文本加密解密测试")
    public void testLongTextEncryption() throws Exception {
        StringBuilder longText = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            longText.append("test").append(i).append(" ");
        }

        String encrypted = CredentialBackupService.encryptData(longText.toString(), TEST_PASSWORD);
        String decrypted = CredentialBackupService.decryptData(encrypted, TEST_PASSWORD);
        assertEquals(longText.toString(), decrypted);
    }

    @Test
    @DisplayName("不同密码产生不同密文")
    public void testDifferentPasswordsProduceDifferentCiphertexts() throws Exception {
        String encrypted1 = CredentialBackupService.encryptData(TEST_PLAINTEXT, "password1abc!");
        String encrypted2 = CredentialBackupService.encryptData(TEST_PLAINTEXT, "password2def!");
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    @DisplayName("相同密码相同明文产生不同密文（由于随机IV，应该不同）")
    public void testSamePasswordSamePlaintextProduceDifferentCiphertexts() throws Exception {
        String encrypted1 = CredentialBackupService.encryptData(TEST_PLAINTEXT, TEST_PASSWORD);
        String encrypted2 = CredentialBackupService.encryptData(TEST_PLAINTEXT, TEST_PASSWORD);
        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    @DisplayName("JSON数据结构加密解密测试")
    public void testJsonStructureEncryption() throws Exception {
        JSONObject json = new JSONObject();
        json.put("version", "1.0");
        json.put("folder", "test-folder");
        json.put("count", 3);

        String originalJson = json.toString();
        String encrypted = CredentialBackupService.encryptData(originalJson, TEST_PASSWORD);
        String decrypted = CredentialBackupService.decryptData(encrypted, TEST_PASSWORD);

        JSONObject resultJson = JSONObject.fromObject(decrypted);
        assertEquals("1.0", resultJson.getString("version"));
        assertEquals("test-folder", resultJson.getString("folder"));
        assertEquals(3, resultJson.getInt("count"));
    }
}
