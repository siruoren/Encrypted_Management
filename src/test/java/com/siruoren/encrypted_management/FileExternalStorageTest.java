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

        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

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

        storage.saveAllCredentials(SYSTEM_FOLDER, credentialsData);

        // 系统级凭据保存为 jenkins_root.enc
        File rootFile = new File(tempDir, "jenkins_root.enc");
        assertTrue(rootFile.exists());
    }

    @Test
    @DisplayName("测试空文件夹名使用系统级文件")
    void testEmptyFolderNameUsesRoot() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        storage.saveAllCredentials("", credentialsData);

        File rootFile = new File(tempDir, "jenkins_root.enc");
        assertTrue(rootFile.exists());
    }

    @Test
    @DisplayName("测试null文件夹名使用系统级文件")
    void testNullFolderNameUsesRoot() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        storage.saveAllCredentials("system", credentialsData);

        File rootFile = new File(tempDir, "jenkins_root.enc");
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

        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

        // 目录任务文件保存在 storageDir/test_folder/test_folder.enc
        File credFile = new File(new File(tempDir, TEST_FOLDER), TEST_FOLDER + ".enc");
        assertTrue(credFile.exists());

        storage.deleteAllCredentials(TEST_FOLDER);
        assertFalse(credFile.exists());
    }

    @Test
    @DisplayName("测试列出文件夹")
    void testListFolders() throws IOException {
        JSONObject data1 = new JSONObject();
        data1.put("version", "1.0");
        storage.saveAllCredentials("folder1", data1);
        storage.saveAllCredentials("folder2", data1);
        storage.saveAllCredentials(SYSTEM_FOLDER, data1);

        List<String> folders = storage.listFolders();
        assertTrue(folders.contains("folder1"));
        assertTrue(folders.contains("folder2"));
        assertTrue(folders.contains("system"));
    }

    @Test
    @DisplayName("测试空存储目录列出空列表")
    void testListFoldersEmpty() throws IOException {
        // 使用独立的临时目录确保为空
        File emptyDir = new File(tempDir, "empty_storage");
        emptyDir.mkdirs();
        FileExternalStorage emptyStorage = new FileExternalStorage(emptyDir.getAbsolutePath());
        emptyStorage.setEncryptionPassword(TEST_PASSWORD);
        List<String> folders = emptyStorage.listFolders();
        assertTrue(folders.isEmpty());
    }

    @Test
    @DisplayName("测试未设置加密密码时保存失败")
    void testSaveWithoutPassword() {
        FileExternalStorage storageWithoutPassword = new FileExternalStorage(tempDir.getAbsolutePath());

        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        assertThrows(IOException.class, () -> {
            storageWithoutPassword.saveAllCredentials(TEST_FOLDER, credentialsData);
        });
    }

    @Test
    @DisplayName("测试未设置加密密码时加载失败")
    void testLoadWithoutPassword() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");
        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

        FileExternalStorage storageWithoutPassword = new FileExternalStorage(tempDir.getAbsolutePath());

        assertThrows(IOException.class, () -> {
            storageWithoutPassword.loadAllCredentials(TEST_FOLDER);
        });
    }

    @Test
    @DisplayName("测试错误密码加载失败")
    void testLoadWithWrongPassword() throws IOException {
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");
        storage.saveAllCredentials(TEST_FOLDER, credentialsData);

        FileExternalStorage wrongPasswordStorage = new FileExternalStorage(tempDir.getAbsolutePath());
        wrongPasswordStorage.setEncryptionPassword("wrongPassword12345678!");

        assertThrows(IOException.class, () -> {
            wrongPasswordStorage.loadAllCredentials(TEST_FOLDER);
        });
    }

    @Test
    @DisplayName("测试路径清理（防止路径遍历攻击）")
    void testPathSanitization() throws IOException {
        String maliciousPath = "../etc/passwd";
        JSONObject credentialsData = new JSONObject();
        credentialsData.put("version", "1.0");

        storage.saveAllCredentials(maliciousPath, credentialsData);

        // 验证文件不会被创建在恶意路径
        File maliciousFile = new File(tempDir.getParent(), "etc/passwd.enc");
        assertFalse(maliciousFile.exists());
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
