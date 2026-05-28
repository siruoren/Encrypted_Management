package com.siruoren.encrypted_management;

import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 基于文件的外部存储实现
 * 凭据存储在自定义目录下，与Jenkins Job配置完全解耦
 * 每个凭据单独保存为一个加密文件，文件名为凭据ID.enc，放在对应目录任务子目录下
 * 系统级凭据放在 jenkins_root/ 子目录下
 * 加密/解密由CryptoService统一提供
 *
 * 存储结构：
 * - 系统级: storageDir/jenkins_root/credId.enc
 * - 目录任务: storageDir/folderName/credId.enc
 * 例如: storageDir/test/my-ssh-key.enc
 *       storageDir/dev/team/db-password.enc
 *
 * 并发优化：
 * - 使用per-folder细粒度锁，避免全局锁阻塞
 * - encryptionPassword使用volatile保证可见性
 * - 写入使用临时文件+原子重命名，防止写入中断导致数据损坏
 */
public class FileExternalStorage implements ExternalStorage {
    private static final Logger LOGGER = Logger.getLogger(FileExternalStorage.class.getName());

    private volatile File storageDir;
    private volatile String encryptionPassword;

    private final ConcurrentHashMap<String, ReentrantLock> folderLocks = new ConcurrentHashMap<>();

    public FileExternalStorage() {
        this.storageDir = new File(Jenkins.get().getRootDir(), "encrypted-management-storage");
        if (!storageDir.exists()) {
            storageDir.mkdirs();
        }
    }

    public FileExternalStorage(String customPath) {
        if (customPath != null && !customPath.trim().isEmpty()) {
            this.storageDir = new File(customPath.trim());
        } else {
            this.storageDir = new File(Jenkins.get().getRootDir(), "encrypted-management-storage");
        }
        if (!storageDir.exists()) {
            storageDir.mkdirs();
        }
    }

    public void setStorageDir(File storageDir) {
        this.storageDir = storageDir;
        if (!this.storageDir.exists()) {
            this.storageDir.mkdirs();
        }
    }

    public void setEncryptionPassword(String password) {
        this.encryptionPassword = password;
    }

    public String getEncryptionPassword() {
        return this.encryptionPassword;
    }

    private ReentrantLock getFolderLock(String folderName) {
        return folderLocks.computeIfAbsent(folderName, k -> new ReentrantLock());
    }

    /**
     * 获取文件夹对应的子目录
     * 系统级: storageDir/jenkins_root/
     * 目录任务: storageDir/folderName/
     */
    private File getFolderDir(String folderName) {
        File currentStorageDir = storageDir;
        if (folderName == null || folderName.isEmpty() || "system".equals(folderName)) {
            return new File(currentStorageDir, "jenkins_root");
        }
        return new File(currentStorageDir, folderName);
    }

    /**
     * 获取单个凭据文件路径
     * storageDir/folderName/credentialId.enc
     */
    private File getCredentialFile(String folderName, String credentialId) {
        File folderDir = getFolderDir(folderName);
        String safeFileName = sanitizeFileName(credentialId);
        return new File(folderDir, safeFileName + ".enc");
    }

    /**
     * 文件名安全处理：替换不合法的文件名字符
     */
    private String sanitizeFileName(String name) {
        if (name == null || name.isEmpty()) return "unknown";
        return name.replaceAll("[/\\\\:*?\"<>|]", "_");
    }

    @Override
    public String getType() {
        return "FILE";
    }

    @Override
    public boolean testConnection() throws IOException {
        return storageDir.exists() && storageDir.isDirectory() && storageDir.canWrite();
    }

    @Override
    public void saveCredential(String folderName, String credentialId, JSONObject credentialData) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File currentStorageDir = storageDir;
            if (!currentStorageDir.exists()) {
                currentStorageDir.mkdirs();
            }

            String currentPassword = encryptionPassword;
            if (currentPassword == null || currentPassword.isEmpty()) {
                throw new IOException("Encryption password is required for external storage");
            }

            String dataToWrite;
            try {
                dataToWrite = CryptoService.aesEncrypt(credentialData.toString(), currentPassword);
            } catch (Exception e) {
                throw new IOException("Failed to encrypt credential data", e);
            }

            File credFile = getCredentialFile(folderName, credentialId);
            File parentDir = credFile.getParentFile();
            if (!parentDir.exists()) {
                parentDir.mkdirs();
            }

            File tempFile = new File(parentDir, credFile.getName() + ".tmp");
            try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
                writer.write(dataToWrite);
            }

            if (!tempFile.renameTo(credFile)) {
                try (Writer writer = new OutputStreamWriter(new FileOutputStream(credFile), StandardCharsets.UTF_8)) {
                    writer.write(dataToWrite);
                }
                tempFile.delete();
            }

            LOGGER.info("Saved credential to external storage: " + credFile.getAbsolutePath() + " (encrypted)");
        } finally {
            lock.unlock();
        }
    }

    @Override
    public JSONObject loadCredential(String folderName, String credentialId) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File credFile = getCredentialFile(folderName, credentialId);
            if (!credFile.exists()) {
                return null;
            }

            String content = new String(Files.readAllBytes(credFile.toPath()), StandardCharsets.UTF_8);

            String currentPassword = encryptionPassword;
            if (currentPassword == null || currentPassword.isEmpty()) {
                throw new IOException("Encryption password is required for external storage");
            }
            try {
                content = CryptoService.aesDecrypt(content, currentPassword);
            } catch (Exception e) {
                throw new IOException("Failed to decrypt credential data", e);
            }

            return JSONObject.fromObject(content);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void deleteCredential(String folderName, String credentialId) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File credFile = getCredentialFile(folderName, credentialId);
            if (credFile.exists()) {
                if (!credFile.delete()) {
                    throw new IOException("Failed to delete credential file: " + credFile.getAbsolutePath());
                }
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<String> listCredentialIds(String folderName) throws IOException {
        File folderDir = getFolderDir(folderName);
        if (!folderDir.exists() || !folderDir.isDirectory()) {
            return Collections.emptyList();
        }

        List<String> ids = new ArrayList<>();
        File[] files = folderDir.listFiles((dir, name) -> name.endsWith(".enc"));
        if (files == null) return ids;

        for (File f : files) {
            String fileName = f.getName();
            ids.add(fileName.substring(0, fileName.length() - 4));
        }
        return ids;
    }

    @Override
    @Deprecated
    public void saveAllCredentials(String folderName, JSONObject allCredentialsData) throws IOException {
        JSONArray credentials = allCredentialsData.optJSONArray("credentials");
        if (credentials == null) return;

        for (int i = 0; i < credentials.size(); i++) {
            JSONObject credObj = credentials.getJSONObject(i);
            String credId = credObj.optString("id", null);
            if (credId == null || credId.isEmpty()) continue;

            JSONObject singleCredData = new JSONObject();
            singleCredData.put("version", allCredentialsData.optString("version", "1.0"));
            singleCredData.put("folder", allCredentialsData.optString("folder", folderName));
            singleCredData.put("exportTime", allCredentialsData.optString("exportTime", java.time.LocalDateTime.now().toString()));
            singleCredData.put("credential", credObj);

            saveCredential(folderName, credId, singleCredData);
        }
    }

    @Override
    @Deprecated
    public JSONObject loadAllCredentials(String folderName) throws IOException {
        List<String> credIds = listCredentialIds(folderName);
        if (credIds.isEmpty()) return null;

        JSONArray credentialsArray = new JSONArray();
        for (String credId : credIds) {
            try {
                JSONObject singleData = loadCredential(folderName, credId);
                if (singleData != null) {
                    JSONObject credObj = singleData.optJSONObject("credential");
                    if (credObj != null) {
                        credentialsArray.add(credObj);
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to load credential: " + credId, e);
            }
        }

        if (credentialsArray.isEmpty()) return null;

        JSONObject result = new JSONObject();
        result.put("version", "1.0");
        result.put("folder", folderName);
        result.put("count", credentialsArray.size());
        result.put("credentials", credentialsArray);
        return result;
    }

    @Override
    public void deleteAllCredentials(String folderName) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File folderDir = getFolderDir(folderName);
            if (!folderDir.exists()) {
                folderLocks.remove(folderName);
                return;
            }

            File[] files = folderDir.listFiles((dir, name) -> name.endsWith(".enc"));
            if (files != null) {
                for (File f : files) {
                    if (!f.delete()) {
                        LOGGER.warning("Failed to delete credential file: " + f.getAbsolutePath());
                    }
                }
            }

            File[] remaining = folderDir.listFiles();
            if (remaining == null || remaining.length == 0) {
                folderDir.delete();
                File currentStorageDir = storageDir;
                File parent = folderDir.getParentFile();
                while (parent != null && !parent.equals(currentStorageDir)) {
                    File[] parentRemaining = parent.listFiles();
                    if (parentRemaining == null || parentRemaining.length == 0) {
                        parent.delete();
                        parent = parent.getParentFile();
                    } else {
                        break;
                    }
                }
            }
            folderLocks.remove(folderName);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<String> listFolders() throws IOException {
        File currentStorageDir = storageDir;
        if (!currentStorageDir.exists() || !currentStorageDir.isDirectory()) {
            return Collections.emptyList();
        }

        Set<String> folders = new HashSet<>();
        listFoldersRecursive(currentStorageDir, currentStorageDir, folders);
        return new ArrayList<>(folders);
    }

    private void listFoldersRecursive(File baseDir, File currentDir, Set<String> folders) {
        File[] children = currentDir.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) {
                File[] encFiles = child.listFiles((dir, name) -> name.endsWith(".enc"));
                if (encFiles != null && encFiles.length > 0) {
                    String relativePath = baseDir.toPath().relativize(child.toPath()).toString();
                    relativePath = relativePath.replace(File.separatorChar, '/');
                    if ("jenkins_root".equals(relativePath)) {
                        folders.add("system");
                    } else if (!relativePath.isEmpty()) {
                        folders.add(relativePath);
                    }
                }
                listFoldersRecursive(baseDir, child, folders);
            }
        }
    }

    @Override
    public JSONObject getConfigInfo() {
        File currentStorageDir = storageDir;
        JSONObject info = new JSONObject();
        info.put("type", getType());
        info.put("path", currentStorageDir.getAbsolutePath());
        info.put("writable", currentStorageDir.canWrite());
        info.put("encrypted", encryptionPassword != null && !encryptionPassword.isEmpty());
        return info;
    }
}
