package com.siruoren.encrypted_management;

import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 外部存储管理器
 * 管理存储后端的注册、选择和同步
 * 支持凭据在Jenkins原生存储和外部存储之间同步
 * 支持加密存储和自定义路径
 *
 * 并发优化：
 * - 使用ReadWriteLock保护配置读写，读多写少场景下提高并发
 * - volatile保证单例的双重检查锁正确性
 * - 配置变更时使用写锁，状态查询使用读锁
 */
public class ExternalStorageManager {
    private static final Logger LOGGER = Logger.getLogger(ExternalStorageManager.class.getName());
    private static volatile ExternalStorageManager instance;

    private FileExternalStorage storage;
    private volatile boolean enabled = false;
    private volatile SyncMode syncMode = SyncMode.MANUAL;
    private volatile String storagePath;
    private volatile char[] encryptionPassword;

    // 读写锁：保护配置的原子性变更（如setStoragePath需要同时更新storage和password）
    private final ReentrantReadWriteLock configLock = new ReentrantReadWriteLock();

    public enum SyncMode {
        MANUAL,       // 手动同步
        AUTO_SYNC,    // 自动双向同步
        EXTERNAL_ONLY // 仅使用外部存储
    }

    private ExternalStorageManager() {
        this.storage = new FileExternalStorage();
    }

    public static ExternalStorageManager getInstance() {
        if (instance == null) {
            synchronized (ExternalStorageManager.class) {
                if (instance == null) {
                    instance = new ExternalStorageManager();
                }
            }
        }
        return instance;
    }

    public ExternalStorage getStorage() {
        configLock.readLock().lock();
        try {
            return storage;
        } finally {
            configLock.readLock().unlock();
        }
    }

    public void setStorage(ExternalStorage storage) {
        configLock.writeLock().lock();
        try {
            if (storage instanceof FileExternalStorage) {
                this.storage = (FileExternalStorage) storage;
            }
        } finally {
            configLock.writeLock().unlock();
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public SyncMode getSyncMode() {
        return syncMode;
    }

    public void setSyncMode(SyncMode syncMode) {
        this.syncMode = syncMode;
    }

    public String getStoragePath() {
        return storagePath;
    }

    public void setStoragePath(String storagePath) {
        configLock.writeLock().lock();
        try {
            this.storagePath = storagePath;
            if (storagePath != null && !storagePath.trim().isEmpty()) {
                FileExternalStorage newStorage = new FileExternalStorage(storagePath);
                // 保留加密密码
                if (this.encryptionPassword != null) {
                    newStorage.setEncryptionPassword(new String(this.encryptionPassword));
                }
                this.storage = newStorage;
            }
        } finally {
            configLock.writeLock().unlock();
        }
    }

    /**
     * 获取加密密码（返回副本，用后需及时擦除）
     */
    public char[] getEncryptionPasswordChars() {
        configLock.readLock().lock();
        try {
            if (encryptionPassword == null) return null;
            return encryptionPassword.clone();
        } finally {
            configLock.readLock().unlock();
        }
    }

    /**
     * @deprecated 使用 getEncryptionPasswordChars() 替代，避免String驻留
     */
    @Deprecated
    public String getEncryptionPassword() {
        char[] chars = getEncryptionPasswordChars();
        if (chars == null) return null;
        try {
            return new String(chars);
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    public void setEncryptionPassword(String password) {
        configLock.writeLock().lock();
        try {
            // 擦除旧密码
            if (this.encryptionPassword != null) {
                Arrays.fill(this.encryptionPassword, '\0');
            }
            this.encryptionPassword = password != null ? password.toCharArray() : null;
            this.storage.setEncryptionPassword(password);
        } finally {
            configLock.writeLock().unlock();
        }
    }

    /**
     * 测试外部存储连接
     */
    public boolean testConnection() {
        configLock.readLock().lock();
        try {
            return storage != null && storage.testConnection();
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "External storage connection test failed", e);
            return false;
        } finally {
            configLock.readLock().unlock();
        }
    }

    /**
     * 获取存储状态信息
     */
    public JSONObject getStatus() {
        configLock.readLock().lock();
        try {
            JSONObject status = new JSONObject();
            status.put("enabled", enabled);
            status.put("syncMode", syncMode.name());
            status.put("storagePath", storagePath != null ? storagePath : "");
            status.put("encrypted", encryptionPassword != null && encryptionPassword.length > 0);
            if (storage != null) {
                status.put("storageType", storage.getType());
                status.put("configInfo", storage.getConfigInfo());
                try {
                    status.put("connected", storage.testConnection());
                } catch (IOException e) {
                    status.put("connected", false);
                    status.put("error", e.getMessage());
                }
            } else {
                status.put("storageType", "NONE");
                status.put("connected", false);
            }
            return status;
        } finally {
            configLock.readLock().unlock();
        }
    }
}
