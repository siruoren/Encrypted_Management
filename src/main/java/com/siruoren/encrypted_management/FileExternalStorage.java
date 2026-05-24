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
 * 支持AES-256-GCM加密存储，每个凭据一个加密JSON文件
 *
 * 并发优化：
 * - 使用per-credential细粒度锁，避免全局锁阻塞
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

    // per-credential细粒度锁，避免全局锁阻塞并发操作
    private final ConcurrentHashMap<String, ReentrantLock> credentialLocks = new ConcurrentHashMap<>();

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
     * 获取凭据级别的锁
     */
    private ReentrantLock getCredentialLock(String folderName, String credentialId) {
        String key = folderName + "/" + credentialId;
        return credentialLocks.computeIfAbsent(key, k -> new ReentrantLock());
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
        ReentrantLock lock = getCredentialLock(folderName, credentialId);
        lock.lock();
        try {
            File currentStorageDir = storageDir; // 快照读取
            File folderDir = new File(currentStorageDir, sanitizePath(folderName));
            if (!folderDir.exists()) {
                folderDir.mkdirs();
            }

            String dataToWrite;
            String currentPassword = encryptionPassword; // 快照读取
            if (currentPassword != null && !currentPassword.isEmpty()) {
                try {
                    dataToWrite = encrypt(credentialData.toString(), currentPassword);
                } catch (Exception e) {
                    throw new IOException("Failed to encrypt credential data", e);
                }
            } else {
                dataToWrite = credentialData.toString();
            }

            // 写入临时文件后原子重命名，防止写入中断导致数据损坏
            File credFile = new File(folderDir, sanitizePath(credentialId) + ".json");
            File tempFile = new File(folderDir, sanitizePath(credentialId) + ".json.tmp");
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

            LOGGER.info("Saved credential to external storage: " + folderName + "/" + credentialId
                    + (currentPassword != null ? " (encrypted)" : ""));
        } finally {
            lock.unlock();
        }
    }

    @Override
    public JSONObject loadCredential(String folderName, String credentialId) throws IOException {
        ReentrantLock lock = getCredentialLock(folderName, credentialId);
        lock.lock();
        try {
            File currentStorageDir = storageDir; // 快照读取
            File credFile = new File(currentStorageDir, sanitizePath(folderName) + "/" + sanitizePath(credentialId) + ".json");
            if (!credFile.exists()) {
                return null;
            }

            String content = new String(Files.readAllBytes(credFile.toPath()), StandardCharsets.UTF_8);

            String currentPassword = encryptionPassword; // 快照读取
            if (currentPassword != null && !currentPassword.isEmpty()) {
                try {
                    content = decrypt(content, currentPassword);
                } catch (Exception e) {
                    throw new IOException("Failed to decrypt credential data", e);
                }
            }

            return JSONObject.fromObject(content);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void deleteCredential(String folderName, String credentialId) throws IOException {
        ReentrantLock lock = getCredentialLock(folderName, credentialId);
        lock.lock();
        try {
            File currentStorageDir = storageDir; // 快照读取
            File credFile = new File(currentStorageDir, sanitizePath(folderName) + "/" + sanitizePath(credentialId) + ".json");
            if (credFile.exists()) {
                if (!credFile.delete()) {
                    throw new IOException("Failed to delete credential file: " + credFile.getAbsolutePath());
                }
            }
            // 清理锁映射，防止内存泄漏
            credentialLocks.remove(folderName + "/" + credentialId);
        } finally {
            lock.unlock();
        }
    }

    @Override
    public List<String> listCredentials(String folderName) throws IOException {
        File currentStorageDir = storageDir; // 快照读取
        File folderDir = new File(currentStorageDir, sanitizePath(folderName));
        if (!folderDir.exists() || !folderDir.isDirectory()) {
            return Collections.emptyList();
        }

        File[] files = folderDir.listFiles((dir, name) -> name.endsWith(".json"));
        if (files == null) {
            return Collections.emptyList();
        }

        List<String> ids = new ArrayList<>();
        for (File f : files) {
            String name = f.getName();
            ids.add(name.substring(0, name.length() - 5));
        }
        return ids;
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
