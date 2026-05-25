package com.siruoren.encrypted_management;

import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 基于文件的外部存储实现
 * 凭据存储在自定义目录下，与Jenkins Job配置完全解耦
 * 每个目录任务的所有凭据保存为一个JSON文件，系统级凭据使用jenkins_root.json
 * 支持AES-256-GCM加密存储
 *
 * 并发优化：
 * - 使用per-folder细粒度锁，避免全局锁阻塞
 * - encryptionPassword使用volatile保证可见性
 * - 写入使用临时文件+原子重命名，防止写入中断导致数据损坏
 */
public class FileExternalStorage implements ExternalStorage {
    private static final Logger LOGGER = Logger.getLogger(FileExternalStorage.class.getName());
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int AES_KEY_LENGTH = 256;

    private volatile File storageDir;
    private volatile String encryptionPassword;

    // per-folder细粒度锁，避免全局锁阻塞并发操作
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

    /**
     * 获取文件夹级别的锁
     */
    private ReentrantLock getFolderLock(String folderName) {
        return folderLocks.computeIfAbsent(folderName, k -> new ReentrantLock());
    }

    /**
     * 根据文件夹名生成JSON文件名
     * 系统级凭据使用jenkins_root.json
     * 目录任务使用目录全名（/替换为_）.json
     */
    private String getFileName(String folderName) {
        if (folderName == null || folderName.isEmpty() || "system".equals(folderName)) {
            return "jenkins_root.json";
        }
        return sanitizePath(folderName) + ".json";
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
    public void saveAllCredentials(String folderName, JSONObject allCredentialsData) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File currentStorageDir = storageDir; // 快照读取
            if (!currentStorageDir.exists()) {
                currentStorageDir.mkdirs();
            }

            String dataToWrite;
            String currentPassword = encryptionPassword; // 快照读取
            if (currentPassword == null || currentPassword.isEmpty()) {
                throw new IOException("Encryption password is required for external storage");
            }
            try {
                dataToWrite = encrypt(allCredentialsData.toString(), currentPassword);
            } catch (Exception e) {
                throw new IOException("Failed to encrypt credential data", e);
            }

            // 写入临时文件后原子重命名，防止写入中断导致数据损坏
            String fileName = getFileName(folderName);
            File credFile = new File(currentStorageDir, fileName);
            File tempFile = new File(currentStorageDir, fileName + ".tmp");
            try (Writer writer = new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8)) {
                writer.write(dataToWrite);
            }

            // 原子重命名
            if (!tempFile.renameTo(credFile)) {
                // 部分文件系统不支持原子重命名，回退到直接写入
                try (Writer writer = new OutputStreamWriter(new FileOutputStream(credFile), StandardCharsets.UTF_8)) {
                    writer.write(dataToWrite);
                }
                tempFile.delete();
            }

            LOGGER.info("Saved credentials to external storage: " + fileName
                    + (currentPassword != null ? " (encrypted)" : ""));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public JSONObject loadAllCredentials(String folderName) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File currentStorageDir = storageDir; // 快照读取
            String fileName = getFileName(folderName);
            File credFile = new File(currentStorageDir, fileName);
            if (!credFile.exists()) {
                return null;
            }

            String content = new String(Files.readAllBytes(credFile.toPath()), StandardCharsets.UTF_8);

            String currentPassword = encryptionPassword; // 快照读取
            if (currentPassword == null || currentPassword.isEmpty()) {
                throw new IOException("Encryption password is required for external storage");
            }
            try {
                content = decrypt(content, currentPassword);
            } catch (Exception e) {
                throw new IOException("Failed to decrypt credential data", e);
            }

            return JSONObject.fromObject(content);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void deleteAllCredentials(String folderName) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File currentStorageDir = storageDir; // 快照读取
            String fileName = getFileName(folderName);
            File credFile = new File(currentStorageDir, fileName);
            if (credFile.exists()) {
                if (!credFile.delete()) {
                    throw new IOException("Failed to delete credential file: " + credFile.getAbsolutePath());
                }
            }
            // 清理锁映射，防止内存泄漏
            folderLocks.remove(folderName);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<String> listFolders() throws IOException {
        File currentStorageDir = storageDir; // 快照读取
        if (!currentStorageDir.exists() || !currentStorageDir.isDirectory()) {
            return Collections.emptyList();
        }

        File[] files = currentStorageDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            return Collections.emptyList();
        }

        List<String> folders = new ArrayList<>();
        for (File f : files) {
            String name = f.getName();
            String folderName = name.substring(0, name.length() - 5); // 去掉.json
            folders.add(folderName);
        }
        return folders;
    }

    @Override
    public JSONObject getConfigInfo() {
        File currentStorageDir = storageDir; // 快照读取
        JSONObject info = new JSONObject();
        info.put("type", getType());
        info.put("path", currentStorageDir.getAbsolutePath());
        info.put("writable", currentStorageDir.canWrite());
        info.put("encrypted", encryptionPassword != null && !encryptionPassword.isEmpty());
        return info;
    }

    /**
     * AES-256-GCM加密
     */
    private static String encrypt(String plaintext, String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        javax.crypto.SecretKey key = deriveKey(password, salt);

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(salt);
        bos.write(iv);
        bos.write(ciphertext);

        return Base64.getEncoder().encodeToString(bos.toByteArray());
    }

    /**
     * AES-256-GCM解密
     */
    private static String decrypt(String encryptedBase64, String password) throws Exception {
        byte[] data = Base64.getDecoder().decode(encryptedBase64);

        byte[] salt = new byte[16];
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(data, 0, salt, 0, 16);
        System.arraycopy(data, 16, iv, 0, GCM_IV_LENGTH);

        int ciphertextLength = data.length - 16 - GCM_IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(data, 16 + GCM_IV_LENGTH, ciphertext, 0, ciphertextLength);

        javax.crypto.SecretKey key = deriveKey(password, salt);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * PBKDF2从密码派生AES-256密钥
     */
    private static javax.crypto.SecretKey deriveKey(String password, byte[] salt) throws Exception {
        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                password.toCharArray(), salt, 65536, AES_KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 清理路径，防止路径遍历攻击
     */
    private String sanitizePath(String path) {
        if (path == null || path.isEmpty()) return "default";
        return path.replaceAll("[/\\\\.]", "_").replaceAll("[^a-zA-Z0-9_\\-]", "");
    }
}
