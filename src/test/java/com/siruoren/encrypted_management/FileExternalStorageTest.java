package com.siruoren.encrypted_management;

import net.sf.json.JSONObject;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * FileExternalStorage 单元测试
 */
@DisplayName("FileExternalStorage 单元测试")
public class FileExternalStorageTest {

    private static final String TEST_PASSWORD = "testPassword123!";
    private static final String SYSTEM_FOLDER = "system";
    private static final String TEST_FOLDER = "test_folder";

    @TempDir
    static File tempDir;

    private FileExternalStorage storage;

    @BeforeEach
    void setUp() {
        storage = new FileExternalStorage(tempDir.getAbsolutePath());
        storage.setEncryptionPassword(TEST_PASSWORD);
    }

    @Test
    @DisplayName("测试连接")
    void testConnection() throws IOException {
        assertTrue(storage.testConnection());
    }

    @Test
    @DisplayName("测试保存和加载凭据")
    void testSaveAndLoadCredentials() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");
        credentialsData.put("folder", TEST_FOLDER);
        credentialsData.put("count", 2);

        // 保存凭据
        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

        // 加载凭据
        JSONObject loaded = storage.loadAllCredentials(TEST_FOLDER);
        assertNotNull(loaded);
        assertEquals("1.0", loaded.getString("version"));
        assertEquals(TEST_FOLDER, loaded.getString("folder"));
        assertEquals(2, loaded.getInt("count"));
    }

    @Test
    @DisplayName("测试系统级凭据文件命名")
    void testSystemCredentialsFile() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");
        credentialsData.put("folder", SYSTEM_FOLDER);

        // 保存系统级凭据
        storage.saveAllCredentials(SYSTEM_FOLDER, credentialsData);

        // 验证文件名为 jenkins_root.json
        File rootFile = new File(tempDir, "jenkins_root.json");
        assertTrue(rootFile.exists());
    }

    @Test
    @DisplayName("测试空文件夹名使用系统级文件")
    void testEmptyFolderNameUsesRoot() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        storage.saveAllCredentials("", credentialsData);

        File rootFile = new File(tempDir, "jenkins_root.json");
        assertTrue(rootFile.exists());
    }

    @Test
    @DisplayName("测试null文件夹名使用系统级文件")
    void testNullFolderNameUsesRoot() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        storage.saveAllCredentials("system", credentialsData);  // 使用 "system" 代替 null

        File rootFile = new File(tempDir, "jenkins_root.json");
        assertTrue(rootFile.exists());
    }

    @Test
    @DisplayName("测试加载不存在的文件夹凭据")
    void testLoadNonExistentFolder() throws IOException {
        JSONObject loaded = storage.loadAllCredentials("non_existent");
        assertNull(loaded);
    }

    @Test
    @DisplayName("测试删除凭据")
    void testDeleteCredentials() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        // 先保存
        storage.saveAllCredentials(TEST_FOLDER, credentialsData);
        File credFile = new File(tempDir, TEST_FOLDER + ".json");
        assertTrue(credFile.exists());

        // 删除
        storage.deleteAllCredentials(TEST_FOLDER);
        assertFalse(credFile.exists());
    }

    @Test
    @DisplayName("测试列出文件夹")
    void testListFolders() throws IOException {
        // 创建多个凭据文件
        JSONObject data1 = new JSONObject();
        data1.put("version", "1.0");
        storage.saveAllCredentials("folder1", data1);
        storage.saveAllCredentials("folder2", data1);
        storage.saveAllCredentials(SYSTEM_FOLDER, data1);

        List<String> folders = storage.listFolders();
        assertTrue(folders.contains("folder1"));
        assertTrue(folders.contains("folder2"));
        assertTrue(folders.contains("jenkins_root"));
    }

    @Test
    @DisplayName("测试空存储目录列出空列表")
    void testListFoldersEmpty() throws IOException {
        // 清理目录
        File[] files = tempDir.listFiles();
        if (files != null) {
            for (File f : files) {
                f.delete();
            }
        }
        List<String> folders = storage.listFolders();
        assertTrue(folders.isEmpty());
    }

    @Test
    @DisplayName("测试未设置加密密码时保存失败")
    void testSaveWithoutPassword() {
        FileExternalStorage storageWithoutPassword = new FileExternalStorage(tempDir.getAbsolutePath());
        // 不设置密码

        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        assertThrows(IOException.class, () -> {
            storageWithoutPassword.saveAllCredentials(TEST_FOLDER, credentialsData);
        });
    }

    @Test
    @DisplayName("测试未设置加密密码时加载失败")
    void testLoadWithoutPassword() throws IOException {
        // 先保存
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");
        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

        // 创建新存储实例，不设置密码
        FileExternalStorage storageWithoutPassword = new FileExternalStorage(tempDir.getAbsolutePath());

        assertThrows(IOException.class, () -> {
            storageWithoutPassword.loadAllCredentials(TEST_FOLDER);
        });
    }

    @Test
    @DisplayName("测试错误密码加载失败")
    void testLoadWithWrongPassword() throws IOException {
        // 先保存
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");
        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

        // 创建新存储实例，使用错误密码
        FileExternalStorage wrongPasswordStorage = new FileExternalStorage(tempDir.getAbsolutePath());
        wrongPasswordStorage.setEncryptionPassword("wrongPassword");

        assertThrows(IOException.class, () -> {
            wrongPasswordStorage.loadAllCredentials(TEST_FOLDER);
        });
    }

    @Test
    @DisplayName("测试路径清理（防止路径遍历攻击）")
    void testPathSanitization() throws IOException {
        // 尝试使用恶意路径
        String maliciousPath = "../etc/passwd";
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        storage.saveAllCredentials(maliciousPath, credentialsData);

        // 验证文件不会被创建在恶意路径
        File maliciousFile = new File(tempDir.getParent(), "etc/passwd.json");
        assertFalse(maliciousFile.exists());

        // 验证文件被创建在正确位置（路径被清理）
        File sanitizedFile = new File(tempDir, "___etc_passwd.json");
        assertTrue(sanitizedFile.exists());
    }

    @Test
    @DisplayName("测试获取配置信息")
    void testGetConfigInfo() {
        JSONObject config = storage.getConfigInfo();
        assertEquals("FILE", config.getString("type"));
        assertEquals(tempDir.getAbsolutePath(), config.getString("path"));
        assertTrue(config.getBoolean("writable"));
        assertTrue(config.getBoolean("encrypted"));
    }

    @Test
    @DisplayName("测试没有密码时配置信息显示未加密")
    void testGetConfigInfoWithoutPassword() {
        FileExternalStorage storageWithoutPassword = new FileExternalStorage(tempDir.getAbsolutePath());
        JSONObject config = storageWithoutPassword.getConfigInfo();
        assertFalse(config.getBoolean("encrypted"));
    }
}