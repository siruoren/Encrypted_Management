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

/**
 * 基于文件的外部存储实现
 * 凭据存储在自定义目录下，与Jenkins Job配置完全解耦
 * 每个目录任务的所有凭据保存为一个加密文件，文件名为任务名.enc，系统级凭据使用jenkins_root.enc
 * 加密/解密由CryptoService统一提供
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
     * 根据文件夹名获取凭据文件
     * 系统级凭据使用 jenkins_root.enc（存储根目录下）
     * 目录任务使用目录全名作为子目录层级，文件名为任务名.enc
     * 例如: folderName="test" → storageDir/test/test.enc
     *       folderName="dev/team" → storageDir/dev/team/team.enc
     */
    private File getCredFile(String folderName) {
        File currentStorageDir = storageDir; // 快照读取
        if (folderName == null || folderName.isEmpty() || "system".equals(folderName)) {
            return new File(currentStorageDir, "jenkins_root.enc");
        }
        // 所有目录任务都放在 fullName 路径的子目录下，文件名为任务名.enc
        int lastSlash = folderName.lastIndexOf('/');
        String taskName = lastSlash > 0 ? folderName.substring(lastSlash + 1) : folderName;
        File subDir = new File(currentStorageDir, folderName);
        return new File(subDir, taskName + ".enc");
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
                dataToWrite = CryptoService.aesEncrypt(allCredentialsData.toString(), currentPassword);
            } catch (Exception e) {
                throw new IOException("Failed to encrypt credential data", e);
            }

            // 写入临时文件后原子重命名，防止写入中断导致数据损坏
            File credFile = getCredFile(folderName);
            File parentDir = credFile.getParentFile();
            if (!parentDir.exists()) {
                parentDir.mkdirs();
            }
            File tempFile = new File(parentDir, credFile.getName() + ".tmp");
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

            LOGGER.info("Saved credentials to external storage: " + credFile.getAbsolutePath()
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
            File credFile = getCredFile(folderName);
            if (!credFile.exists()) {
                return null;
            }

            String content = new String(Files.readAllBytes(credFile.toPath()), StandardCharsets.UTF_8);

            String currentPassword = encryptionPassword; // 快照读取
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
    public void deleteAllCredentials(String folderName) throws IOException {
        ReentrantLock lock = getFolderLock(folderName);
        lock.lock();
        try {
            File credFile = getCredFile(folderName);
            if (credFile.exists()) {
                if (!credFile.delete()) {
                    throw new IOException("Failed to delete credential file: " + credFile.getAbsolutePath());
                }
                // 删除空父目录（向上递归清理，直到存储根目录）
                File parent = credFile.getParentFile();
                File currentStorageDir = storageDir; // 快照读取
                while (parent != null && !parent.equals(currentStorageDir)) {
                    File[] remaining = parent.listFiles();
                    if (remaining == null || remaining.length == 0) {
                        parent.delete();
                        parent = parent.getParentFile();
                    } else {
                        break;
                    }
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

        List<String> folders = new ArrayList<>();
        // 检查系统级凭据
        if (new File(currentStorageDir, "jenkins_root.enc").exists()) {
            folders.add("system");
        }
        // 递归查找所有 .enc 文件
        listFoldersRecursive(currentStorageDir, currentStorageDir, folders);
        return folders;
    }

    /**
     * 递归查找所有 .enc 文件，计算相对路径作为 folderName
     * 新路径格式: storageDir/test/test.enc → folderName="test"
     *            storageDir/dev/team/team.enc → folderName="dev/team"
     * 即 .enc 文件所在目录的相对路径就是 folderName
     */
    private void listFoldersRecursive(File baseDir, File currentDir, List<String> folders) {
        File[] children = currentDir.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) {
                listFoldersRecursive(baseDir, child, folders);
            } else if (child.getName().endsWith(".enc") && !"jenkins_root.enc".equals(child.getName())) {
                // .enc 文件所在目录的相对路径就是 folderName
                File parentDir = child.getParentFile();
                String relativePath = baseDir.toPath().relativize(parentDir.toPath()).toString();
                // 统一使用 / 作为分隔符
                relativePath = relativePath.replace(File.separatorChar, '/');
                if (!relativePath.isEmpty()) {
                    folders.add(relativePath);
                }
            }
        }
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

}
