package com.siruoren.encrypted_management;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

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
    @DisplayName("测试保存和加载单个凭据")
    void testSaveAndLoadSingleCredential() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "my-cred-1");
        credData.put("type", "USERNAME_PASSWORD");
        credData.put("username", "admin");
        credData.put("password", "secret123");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("folder", TEST_FOLDER);
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, "my-cred-1", singleExport);

        JSONObject loaded = storage.loadCredential(TEST_FOLDER, "my-cred-1");
        assertNotNull(loaded);
        assertEquals("1.0", loaded.getString("version"));
        assertEquals(TEST_FOLDER, loaded.getString("folder"));

        JSONObject loadedCred = loaded.getJSONObject("credential");
        assertEquals("my-cred-1", loadedCred.getString("id"));
        assertEquals("USERNAME_PASSWORD", loadedCred.getString("type"));
        assertEquals("admin", loadedCred.getString("username"));
        assertEquals("secret123", loadedCred.getString("password"));
    }

    @Test
    @DisplayName("测试凭据文件路径 - 系统级")
    void testSystemCredentialFilePath() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "system-cred");
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("folder", SYSTEM_FOLDER);
        singleExport.put("credential", credData);

        storage.saveCredential(SYSTEM_FOLDER, "system-cred", singleExport);

        File credFile = new File(new File(tempDir, "jenkins_root"), "system-cred.enc");
        assertTrue(credFile.exists());
    }

    @Test
    @DisplayName("测试凭据文件路径 - 目录任务级")
    void testFolderCredentialFilePath() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "db-password");
        credData.put("type", "USERNAME_PASSWORD");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("folder", "dev/team");
        singleExport.put("credential", credData);

        storage.saveCredential("dev/team", "db-password", singleExport);

        File credFile = new File(new File(new File(tempDir, "dev"), "team"), "db-password.enc");
        assertTrue(credFile.exists());
    }

    @Test
    @DisplayName("测试凭据ID含特殊字符时文件名安全处理")
    void testCredentialIdWithSpecialChars() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "cred/with:special*chars");
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, "cred/with:special*chars", singleExport);

        File credFile = new File(new File(tempDir, TEST_FOLDER), "cred_with_special_chars.enc");
        assertTrue(credFile.exists());

        JSONObject loaded = storage.loadCredential(TEST_FOLDER, "cred/with:special*chars");
        assertNotNull(loaded);
        JSONObject loadedCred = loaded.getJSONObject("credential");
        assertEquals("cred/with:special*chars", loadedCred.getString("id"));
    }

    @Test
    @DisplayName("测试加载不存在的凭据返回null")
    void testLoadNonExistentCredential() throws IOException {
        JSONObject loaded = storage.loadCredential(TEST_FOLDER, "non-existent-cred");
        assertNull(loaded);
    }

    @Test
    @DisplayName("测试删除单个凭据")
    void testDeleteSingleCredential() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "cred-to-delete");
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, "cred-to-delete", singleExport);
        assertNotNull(storage.loadCredential(TEST_FOLDER, "cred-to-delete"));

        storage.deleteCredential(TEST_FOLDER, "cred-to-delete");
        assertNull(storage.loadCredential(TEST_FOLDER, "cred-to-delete"));
    }

    @Test
    @DisplayName("测试列出凭据ID")
    void testListCredentialIds() throws IOException {
        for (int i = 1; i <= 3; i++) {
            JSONObject credData = new JSONObject();
            credData.put("id", "cred-" + i);
            credData.put("type", "SECRET_TEXT");

            JSONObject singleExport = new JSONObject();
            singleExport.put("version", "1.0");
            singleExport.put("credential", credData);

            storage.saveCredential(TEST_FOLDER, "cred-" + i, singleExport);
        }

        List<String> ids = storage.listCredentialIds(TEST_FOLDER);
        assertEquals(3, ids.size());
        assertTrue(ids.contains("cred-1"));
        assertTrue(ids.contains("cred-2"));
        assertTrue(ids.contains("cred-3"));
    }

    @Test
    @DisplayName("测试列出空文件夹凭据ID")
    void testListCredentialIdsEmpty() throws IOException {
        List<String> ids = storage.listCredentialIds("non_existent");
        assertTrue(ids.isEmpty());
    }

    @Test
    @DisplayName("测试兼容旧格式 - saveAllCredentials拆分为单凭据文件")
    void testSaveAllCredentialsBackwardCompat() throws IOException {
        JSONObject cred1 = new JSONObject();
        cred1.put("id", "cred-1");
        cred1.put("type", "USERNAME_PASSWORD");
        cred1.put("username", "user1");

        JSONObject cred2 = new JSONObject();
        cred2.put("id", "cred-2");
        cred2.put("type", "SECRET_TEXT");

        JSONArray credArray = new JSONArray();
        credArray.add(cred1);
        credArray.add(cred2);

        JSONObject allData = new JSONObject();
        allData.put("version", "1.0");
        allData.put("folder", TEST_FOLDER);
        allData.put("count", 2);
        allData.put("credentials", credArray);

        storage.saveAllCredentials(TEST_FOLDER, allData);

        List<String> ids = storage.listCredentialIds(TEST_FOLDER);
        assertEquals(2, ids.size());
        assertTrue(ids.contains("cred-1"));
        assertTrue(ids.contains("cred-2"));

        JSONObject loaded1 = storage.loadCredential(TEST_FOLDER, "cred-1");
        assertNotNull(loaded1);
        assertEquals("cred-1", loaded1.getJSONObject("credential").getString("id"));
    }

    @Test
    @DisplayName("测试兼容旧格式 - loadAllCredentials聚合单凭据文件")
    void testLoadAllCredentialsBackwardCompat() throws IOException {
        File isolatedDir = new File(tempDir, "isolated_load_all");
        isolatedDir.mkdirs();
        FileExternalStorage isolatedStorage = new FileExternalStorage(isolatedDir.getAbsolutePath());
        isolatedStorage.setEncryptionPassword(TEST_PASSWORD);

        for (int i = 1; i <= 2; i++) {
            JSONObject credData = new JSONObject();
            credData.put("id", "cred-" + i);
            credData.put("type", "SECRET_TEXT");

            JSONObject singleExport = new JSONObject();
            singleExport.put("version", "1.0");
            singleExport.put("folder", TEST_FOLDER);
            singleExport.put("credential", credData);

            isolatedStorage.saveCredential(TEST_FOLDER, "cred-" + i, singleExport);
        }

        JSONObject allData = isolatedStorage.loadAllCredentials(TEST_FOLDER);
        assertNotNull(allData);
        assertEquals(2, allData.getInt("count"));
        assertEquals(2, allData.getJSONArray("credentials").size());
    }

    @Test
    @DisplayName("测试删除所有凭据")
    void testDeleteAllCredentials() throws IOException {
        for (int i = 1; i <= 3; i++) {
            JSONObject credData = new JSONObject();
            credData.put("id", "cred-" + i);
            credData.put("type", "SECRET_TEXT");

            JSONObject singleExport = new JSONObject();
            singleExport.put("version", "1.0");
            singleExport.put("credential", credData);

            storage.saveCredential(TEST_FOLDER, "cred-" + i, singleExport);
        }

        File folderDir = new File(tempDir, TEST_FOLDER);
        assertTrue(folderDir.exists());

        storage.deleteAllCredentials(TEST_FOLDER);
        assertFalse(folderDir.exists());
        assertTrue(storage.listCredentialIds(TEST_FOLDER).isEmpty());
    }

    @Test
    @DisplayName("测试列出文件夹")
    void testListFolders() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "test-cred");
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential("folder1", "test-cred", singleExport);
        storage.saveCredential("folder2", "test-cred", singleExport);
        storage.saveCredential(SYSTEM_FOLDER, "test-cred", singleExport);

        List<String> folders = storage.listFolders();
        assertTrue(folders.contains("folder1"));
        assertTrue(folders.contains("folder2"));
        assertTrue(folders.contains("system"));
    }

    @Test
    @DisplayName("测试空存储目录列出空列表")
    void testListFoldersEmpty() throws IOException {
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

        JSONObject credData = new JSONObject();
        credData.put("id", "test-cred");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        assertThrows(IOException.class, () -> {
            storageWithoutPassword.saveCredential(TEST_FOLDER, "test-cred", singleExport);
        });
    }

    @Test
    @DisplayName("测试未设置加密密码时加载失败")
    void testLoadWithoutPassword() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "test-cred");
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, "test-cred", singleExport);

        FileExternalStorage storageWithoutPassword = new FileExternalStorage(tempDir.getAbsolutePath());

        assertThrows(IOException.class, () -> {
            storageWithoutPassword.loadCredential(TEST_FOLDER, "test-cred");
        });
    }

    @Test
    @DisplayName("测试错误密码加载失败")
    void testLoadWithWrongPassword() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "test-cred");
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, "test-cred", singleExport);

        FileExternalStorage wrongPasswordStorage = new FileExternalStorage(tempDir.getAbsolutePath());
        wrongPasswordStorage.setEncryptionPassword("wrongPassword12345678!");

        assertThrows(IOException.class, () -> {
            wrongPasswordStorage.loadCredential(TEST_FOLDER, "test-cred");
        });
    }

    @Test
    @DisplayName("测试路径清理（防止路径遍历攻击）")
    void testPathSanitization() throws IOException {
        String maliciousId = "../../../etc/passwd";
        JSONObject credData = new JSONObject();
        credData.put("id", maliciousId);
        credData.put("type", "SECRET_TEXT");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, maliciousId, singleExport);

        File maliciousFile = new File(tempDir.getParent(), "etc/passwd.enc");
        assertFalse(maliciousFile.exists());

        File folderDir = new File(tempDir, TEST_FOLDER);
        File[] encFiles = folderDir.listFiles((dir, name) -> name.endsWith(".enc"));
        assertNotNull(encFiles);
        assertTrue(encFiles.length > 0);
        String savedFileName = encFiles[0].getName();
        assertTrue(savedFileName.endsWith(".enc"));
        assertFalse(savedFileName.contains(".."));
        assertFalse(savedFileName.contains("/"));
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

    @Test
    @DisplayName("测试覆盖更新单个凭据")
    void testOverwriteCredential() throws IOException {
        JSONObject credData = new JSONObject();
        credData.put("id", "my-cred");
        credData.put("type", "USERNAME_PASSWORD");
        credData.put("username", "old-user");

        JSONObject singleExport = new JSONObject();
        singleExport.put("version", "1.0");
        singleExport.put("credential", credData);

        storage.saveCredential(TEST_FOLDER, "my-cred", singleExport);

        credData.put("username", "new-user");
        singleExport.put("credential", credData);
        storage.saveCredential(TEST_FOLDER, "my-cred", singleExport);

        JSONObject loaded = storage.loadCredential(TEST_FOLDER, "my-cred");
        assertEquals("new-user", loaded.getJSONObject("credential").getString("username"));
    }

    @Test
    @DisplayName("测试多文件夹独立存储")
    void testMultipleFolderIsolation() throws IOException {
        JSONObject credData1 = new JSONObject();
        credData1.put("id", "same-id");
        credData1.put("type", "SECRET_TEXT");
        credData1.put("secret", "folder1-secret");

        JSONObject export1 = new JSONObject();
        export1.put("version", "1.0");
        export1.put("folder", "folder1");
        export1.put("credential", credData1);

        JSONObject credData2 = new JSONObject();
        credData2.put("id", "same-id");
        credData2.put("type", "SECRET_TEXT");
        credData2.put("secret", "folder2-secret");

        JSONObject export2 = new JSONObject();
        export2.put("version", "1.0");
        export2.put("folder", "folder2");
        export2.put("credential", credData2);

        storage.saveCredential("folder1", "same-id", export1);
        storage.saveCredential("folder2", "same-id", export2);

        JSONObject loaded1 = storage.loadCredential("folder1", "same-id");
        JSONObject loaded2 = storage.loadCredential("folder2", "same-id");

        assertEquals("folder1-secret", loaded1.getJSONObject("credential").getString("secret"));
        assertEquals("folder2-secret", loaded2.getJSONObject("credential").getString("secret"));
    }
}
