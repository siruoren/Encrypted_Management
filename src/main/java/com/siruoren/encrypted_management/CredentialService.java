package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.model.ItemGroup;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 凭据操作统一服务类
 * <p>
 * 集中管理凭据的CRUD、解密、密钥生成等核心逻辑，
 * 消除SystemCredentialsAction和EncryptedManagementAction之间的代码重复。
 * <p>
 * 安全措施：
 * - XSS防护：所有返回前端的用户可控字段进行HTML转义
 * - 异常处理：捕获具体异常，前端返回通用错误提示，详细错误仅记录服务端
 * - ID校验：系统级凭据强制要求id不为空
 * - 并发安全：凭据存储写操作使用per-store锁保证原子性
 * - 输入校验：长度和格式验证
 */
public class CredentialService {
    private static final Logger LOGGER = Logger.getLogger(CredentialService.class.getName());

    /** 输入长度限制 */
    private static final int MAX_ID_LENGTH = 255;
    private static final int MAX_DESCRIPTION_LENGTH = 1024;
    private static final int MAX_SECRET_LENGTH = 65536;
    private static final int MAX_USERNAME_LENGTH = 255;
    private static final int MAX_PASSWORD_LENGTH = 65536;
    private static final int MAX_PRIVATE_KEY_LENGTH = 65536;
    private static final int MAX_PASSPHRASE_LENGTH = 1024;

    /** 安全配置：文件大小限制 */
    public static final int MAX_ZIP_SIZE_BYTES = 20 * 1024 * 1024; // 20MB
    public static final int MAX_CREDENTIALS_PER_IMPORT = 1000;
    public static final int MAX_ZIP_ENTRIES = 500;

    /** Per-store 细粒度锁，保证凭据写操作原子性 */
    private static final ConcurrentHashMap<String, ReentrantLock> storeLocks = new ConcurrentHashMap<>();

    private CredentialService() {}

    // ==================== 锁管理 ====================

    private static ReentrantLock getStoreLock(Object context) {
        String key = context instanceof hudson.model.Item
                ? ((hudson.model.Item) context).getFullName()
                : "system";
        return storeLocks.computeIfAbsent(key, k -> new ReentrantLock());
    }

    // ==================== HTML转义（XSS防护） ====================

    /**
     * HTML转义，防止XSS攻击
     */
    public static String escapeHtml(String input) {
        if (input == null) return "";
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }

    // ==================== 输入校验 ====================

    public static void validateId(String id, boolean required) throws ValidationException {
        if (id == null || id.isEmpty()) {
            if (required) {
                throw new ValidationException("Credential ID is required");
            }
            return;
        }
        if (id.length() > MAX_ID_LENGTH) {
            throw new ValidationException("Credential ID exceeds maximum length (" + MAX_ID_LENGTH + ")");
        }
    }

    public static void validateDescription(String description) throws ValidationException {
        if (description != null && description.length() > MAX_DESCRIPTION_LENGTH) {
            throw new ValidationException("Description exceeds maximum length (" + MAX_DESCRIPTION_LENGTH + ")");
        }
    }

    public static void validateSecret(String secret) throws ValidationException {
        if (secret == null || secret.trim().isEmpty()) {
            throw new ValidationException("Secret value is required");
        }
        if (secret.length() > MAX_SECRET_LENGTH) {
            throw new ValidationException("Secret value exceeds maximum length");
        }
    }

    public static void validateUsername(String username) throws ValidationException {
        if (username == null || username.trim().isEmpty()) {
            throw new ValidationException("Username is required");
        }
        if (username.length() > MAX_USERNAME_LENGTH) {
            throw new ValidationException("Username exceeds maximum length");
        }
    }

    public static void validatePassword(String password) throws ValidationException {
        if (password == null || password.trim().isEmpty()) {
            throw new ValidationException("Password is required");
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new ValidationException("Password exceeds maximum length");
        }
    }

    public static void validatePrivateKey(String privateKey) throws ValidationException {
        if (privateKey == null || privateKey.trim().isEmpty()) {
            throw new ValidationException("Private key is required");
        }
        if (privateKey.length() > MAX_PRIVATE_KEY_LENGTH) {
            throw new ValidationException("Private key exceeds maximum length");
        }
        if (!privateKey.contains("-----BEGIN")) {
            throw new ValidationException("Private key must be in PEM format");
        }
    }

    public static void validatePassphrase(String passphrase) throws ValidationException {
        if (passphrase != null && passphrase.length() > MAX_PASSPHRASE_LENGTH) {
            throw new ValidationException("Passphrase exceeds maximum length");
        }
    }

    /** 校验异常 */
    public static class ValidationException extends Exception {
        public ValidationException(String message) {
            super(message);
        }
    }

    // ==================== 凭据存储操作 ====================

    /**
     * 查找ItemGroup的凭据存储
     */
    public static CredentialsStore findStore(ItemGroup<?> itemGroup) {
        for (CredentialsStore store : CredentialsProvider.lookupStores(itemGroup)) {
            if (store.getContext() == itemGroup) {
                return store;
            }
        }
        return null;
    }

    /**
     * 获取ItemGroup自身凭据存储中的凭据列表
     */
    public static List<StandardCredentials> getStoreCredentials(ItemGroup<?> itemGroup) {
        List<StandardCredentials> result = new ArrayList<>();
        CredentialsStore store = findStore(itemGroup);
        if (store != null) {
            for (Domain domain : store.getDomains()) {
                for (com.cloudbees.plugins.credentials.Credentials c : store.getCredentials(domain)) {
                    if (c instanceof StandardCredentials) {
                        result.add((StandardCredentials) c);
                    }
                }
            }
        }
        return result;
    }

    /**
     * 根据ID查找凭据
     */
    public static StandardCredentials findCredentialById(ItemGroup<?> itemGroup, String id) {
        if (id == null || id.isEmpty()) return null;
        for (StandardCredentials c : getStoreCredentials(itemGroup)) {
            if (c.getId().equals(id)) {
                return c;
            }
        }
        return null;
    }

    // ==================== 列表凭据（XSS安全） ====================

    /**
     * 列出凭据（返回JSON数组，所有字段已HTML转义）
     */
    public static JSONArray listCredentialsJson(ItemGroup<?> itemGroup) {
        JSONArray arr = new JSONArray();
        List<StandardCredentials> creds = getStoreCredentials(itemGroup);

        for (StandardCredentials c : creds) {
            JSONObject obj = new JSONObject();
            obj.put("id", escapeHtml(c.getId()));
            obj.put("description", escapeHtml(c.getDescription()));
            obj.put("type", getCredentialsTypeName(c));
            obj.put("typeKey", getCredentialsTypeKey(c));

            if (c instanceof UsernamePasswordCredentials) {
                obj.put("username", escapeHtml(((UsernamePasswordCredentials) c).getUsername()));
            } else if (c instanceof BasicSSHUserPrivateKey) {
                obj.put("username", escapeHtml(((BasicSSHUserPrivateKey) c).getUsername()));
            } else if (c instanceof org.jenkinsci.plugins.plaincredentials.FileCredentials) {
                obj.put("fileName", escapeHtml(((org.jenkinsci.plugins.plaincredentials.FileCredentials) c).getFileName()));
            }

            arr.add(obj);
        }
        return arr;
    }

    // ==================== 解密凭据（XSS安全） ====================

    /**
     * 解密凭据（返回JSON对象，敏感字段不转义以保持原始值，非敏感字段转义）
     */
    public static JSONObject decryptCredentialJson(ItemGroup<?> itemGroup, String id) throws IOException {
        StandardCredentials c = findCredentialById(itemGroup, id);
        if (c == null) {
            throw new IOException("Credential not found: " + id);
        }

        JSONObject result = new JSONObject();
        result.put("id", escapeHtml(id));
        result.put("type", getCredentialsTypeName(c));
        result.put("typeKey", getCredentialsTypeKey(c));

        if (c instanceof UsernamePasswordCredentials) {
            UsernamePasswordCredentials upc = (UsernamePasswordCredentials) c;
            result.put("username", escapeHtml(upc.getUsername()));
            result.put("password", Secret.toString(upc.getPassword()));
        } else if (c instanceof StringCredentials) {
            result.put("secret", Secret.toString(((StringCredentials) c).getSecret()));
        } else if (c instanceof BasicSSHUserPrivateKey) {
            BasicSSHUserPrivateKey ssh = (BasicSSHUserPrivateKey) c;
            result.put("username", escapeHtml(ssh.getUsername()));
            result.put("passphrase", Secret.toString(ssh.getPassphrase()));
            result.put("privateKey", ssh.getPrivateKey());
            String publicKey = CryptoService.derivePublicKey(ssh.getPrivateKey(), ssh.getPassphrase());
            if (publicKey != null && !publicKey.isEmpty()) {
                result.put("publicKey", publicKey);
            }
        } else if (c instanceof org.jenkinsci.plugins.plaincredentials.FileCredentials) {
            org.jenkinsci.plugins.plaincredentials.FileCredentials fc =
                    (org.jenkinsci.plugins.plaincredentials.FileCredentials) c;
            result.put("fileName", escapeHtml(fc.getFileName()));
            try {
                java.io.InputStream is = fc.getContent();
                if (is != null) {
                    byte[] fileBytes = is.readAllBytes();
                    is.close();
                    result.put("fileContent", java.util.Base64.getEncoder().encodeToString(fileBytes));
                    result.put("fileSize", fileBytes.length);
                }
            } catch (IOException e) {
                result.put("fileContent", "");
                result.put("fileSize", 0);
            }
        } else if (c instanceof com.cloudbees.plugins.credentials.common.CertificateCredentials) {
            com.cloudbees.plugins.credentials.common.CertificateCredentials cc =
                    (com.cloudbees.plugins.credentials.common.CertificateCredentials) c;
            if (cc instanceof com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl) {
                com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl cci =
                        (com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl) cc;
                com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl.KeyStoreSource ksSource = cci.getKeyStoreSource();
                if (ksSource instanceof com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl.UploadedKeyStoreSource) {
                    com.cloudbees.plugins.credentials.SecretBytes uploadedKeystore =
                            ((com.cloudbees.plugins.credentials.impl.CertificateCredentialsImpl.UploadedKeyStoreSource) ksSource).getUploadedKeystore();
                    if (uploadedKeystore != null) {
                        result.put("keyStoreSize", uploadedKeystore.getPlainData().length);
                    }
                } else {
                    byte[] ksBytes = ksSource.getKeyStoreBytes();
                    if (ksBytes != null) {
                        result.put("keyStoreSize", ksBytes.length);
                    }
                }
            }
            result.put("keyStorePassword", Secret.toString(cc.getPassword()));
        }

        return result;
    }

    // ==================== 创建凭据（带锁+校验） ====================

    /**
     * 创建Secret Text凭据
     */
    public static StringCredentialsImpl createSecretText(ItemGroup<?> itemGroup, String id, String description, String secret, boolean idRequired)
            throws ValidationException, IOException {
        validateId(id, idRequired);
        validateDescription(description);
        validateSecret(secret);

        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        StringCredentialsImpl credential = new StringCredentialsImpl(
                CredentialsScope.GLOBAL,
                (id != null && !id.isEmpty()) ? id : null,
                description,
                Secret.fromString(secret));

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            store.addCredentials(Domain.global(), credential);
        } finally {
            lock.unlock();
        }
        return credential;
    }

    /**
     * 创建Username/Password凭据
     */
    public static UsernamePasswordCredentialsImpl createUsernamePassword(ItemGroup<?> itemGroup, String id, String description, String username, String password, boolean idRequired)
            throws ValidationException, IOException {
        validateId(id, idRequired);
        validateDescription(description);
        validateUsername(username);
        validatePassword(password);

        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        UsernamePasswordCredentialsImpl credential;
        try {
            credential = new UsernamePasswordCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    username,
                    password);
        } catch (hudson.model.Descriptor.FormException e) {
            throw new IOException("Invalid credential parameters", e);
        }

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            store.addCredentials(Domain.global(), credential);
        } finally {
            lock.unlock();
        }
        return credential;
    }

    /**
     * 创建SSH凭据
     */
    public static BasicSSHUserPrivateKey createSSHKey(ItemGroup<?> itemGroup, String id, String description, String username, String passphrase, String privateKey, boolean idRequired)
            throws ValidationException, IOException {
        validateId(id, idRequired);
        validateDescription(description);
        validateUsername(username);
        validatePassphrase(passphrase);
        validatePrivateKey(privateKey);

        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        BasicSSHUserPrivateKey.DirectEntryPrivateKeySource source =
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(privateKey);

        BasicSSHUserPrivateKey credential = new BasicSSHUserPrivateKey(
                CredentialsScope.GLOBAL,
                (id != null && !id.isEmpty()) ? id : null,
                username,
                source,
                passphrase != null ? passphrase : "",
                description);

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            store.addCredentials(Domain.global(), credential);
        } finally {
            lock.unlock();
        }
        return credential;
    }

    // ==================== 更新凭据（带锁） ====================

    /**
     * 更新Secret Text凭据
     */
    public static void updateSecretText(ItemGroup<?> itemGroup, String id, String description, String secret)
            throws IOException {
        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        StandardCredentials existing = findCredentialById(itemGroup, id);
        if (existing == null) {
            throw new IOException("Credential not found: " + id);
        }
        if (!(existing instanceof StringCredentials)) {
            throw new IOException("Credential is not a Secret Text type");
        }

        StringCredentialsImpl updated = new StringCredentialsImpl(
                CredentialsScope.GLOBAL,
                id,
                description != null ? description : existing.getDescription(),
                Secret.fromString(secret != null ? secret : Secret.toString(((StringCredentials) existing).getSecret())));

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            store.updateCredentials(Domain.global(), existing, updated);
        } finally {
            lock.unlock();
        }
    }

    /**
     * 更新Username/Password凭据
     */
    public static void updateUsernamePassword(ItemGroup<?> itemGroup, String id, String description, String username, String password)
            throws IOException {
        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        StandardCredentials existing = findCredentialById(itemGroup, id);
        if (existing == null) {
            throw new IOException("Credential not found: " + id);
        }
        if (!(existing instanceof UsernamePasswordCredentials)) {
            throw new IOException("Credential is not a Username/Password type");
        }

        UsernamePasswordCredentials oldCred = (UsernamePasswordCredentials) existing;
        UsernamePasswordCredentialsImpl updated;
        try {
            updated = new UsernamePasswordCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    id,
                    description != null ? description : existing.getDescription(),
                    username != null ? username : oldCred.getUsername(),
                    password != null ? password : Secret.toString(oldCred.getPassword()));
        } catch (hudson.model.Descriptor.FormException e) {
            throw new IOException("Invalid credential parameters", e);
        }

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            store.updateCredentials(Domain.global(), existing, updated);
        } finally {
            lock.unlock();
        }
    }

    /**
     * 更新SSH凭据
     */
    public static void updateSSHKey(ItemGroup<?> itemGroup, String id, String description, String username, String passphrase, String privateKey)
            throws IOException {
        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        StandardCredentials existing = findCredentialById(itemGroup, id);
        if (existing == null) {
            throw new IOException("Credential not found: " + id);
        }
        if (!(existing instanceof BasicSSHUserPrivateKey)) {
            throw new IOException("Credential is not an SSH Key type");
        }

        BasicSSHUserPrivateKey oldCred = (BasicSSHUserPrivateKey) existing;
        String resolvedPrivateKey = privateKey != null && !privateKey.isEmpty() ? privateKey : oldCred.getPrivateKey();
        BasicSSHUserPrivateKey.DirectEntryPrivateKeySource newSource =
                new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(resolvedPrivateKey);
        BasicSSHUserPrivateKey updated = new BasicSSHUserPrivateKey(
                CredentialsScope.GLOBAL,
                id,
                username != null ? username : oldCred.getUsername(),
                newSource,
                passphrase != null ? passphrase : Secret.toString(oldCred.getPassphrase()),
                description != null ? description : existing.getDescription());

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            store.updateCredentials(Domain.global(), existing, updated);
        } finally {
            lock.unlock();
        }
    }

    // ==================== 删除凭据（带锁） ====================

    /**
     * 删除凭据
     */
    public static boolean deleteCredential(ItemGroup<?> itemGroup, String id) throws IOException {
        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found");
        }

        StandardCredentials c = findCredentialById(itemGroup, id);
        if (c == null) {
            throw new IOException("Credential not found: " + id);
        }

        ReentrantLock lock = getStoreLock(itemGroup);
        lock.lock();
        try {
            return store.removeCredentials(Domain.global(), c);
        } finally {
            lock.unlock();
        }
    }

    // ==================== 类型判断工具 ====================

    public static String getCredentialsTypeName(StandardCredentials c) {
        if (c instanceof UsernamePasswordCredentials) {
            return "Username with password";
        } else if (c instanceof BasicSSHUserPrivateKey) {
            return "SSH Username with private key";
        } else if (c instanceof StringCredentials) {
            return "Secret text";
        } else if (c instanceof org.jenkinsci.plugins.plaincredentials.FileCredentials) {
            return "Secret file";
        } else if (c instanceof com.cloudbees.plugins.credentials.common.CertificateCredentials) {
            return "Certificate";
        }
        return c.getClass().getSimpleName();
    }

    public static String getCredentialsTypeKey(StandardCredentials c) {
        if (c instanceof UsernamePasswordCredentials) {
            return "USERNAME_PASSWORD";
        } else if (c instanceof BasicSSHUserPrivateKey) {
            return "SSH_KEY";
        } else if (c instanceof StringCredentials) {
            return "SECRET_TEXT";
        } else if (c instanceof org.jenkinsci.plugins.plaincredentials.FileCredentials) {
            return "SECRET_FILE";
        } else if (c instanceof com.cloudbees.plugins.credentials.common.CertificateCredentials) {
            return "CERTIFICATE";
        }
        return "OTHER";
    }

    // ==================== 通用错误处理 ====================

    /**
     * 安全错误消息：前端返回通用提示，详细错误仅记录服务端
     */
    public static String safeErrorMessage(String operation, Exception e) {
        LOGGER.log(Level.SEVERE, "Failed to " + operation, e);
        // 不向用户暴露内部异常信息
        if (e instanceof ValidationException) {
            return e.getMessage(); // 校验错误可以返回给用户
        }
        if (e instanceof IOException) {
            return e.getMessage(); // IO错误消息通常是安全的
        }
        return "Failed to " + operation + ". Please check server logs for details.";
    }

    // ==================== JSON Schema 验证 ====================

    /** 允许的凭据类型白名单 */
    private static final java.util.Set<String> ALLOWED_CREDENTIAL_TYPES = java.util.Set.of(
            "USERNAME_PASSWORD", "SSH_KEY", "SECRET_TEXT", "SECRET_FILE", "CERTIFICATE"
    );

    /** 允许的JSON字段白名单 */
    private static final java.util.Set<String> ALLOWED_FIELDS = java.util.Set.of(
            "id", "description", "scope", "type",
            "username", "password", "secret", "privateKey", "passphrase", "publicKey",
            "fileName", "fileContent", "keyStoreBytes", "keyStorePassword"
    );

    /**
     * 验证导入的凭据JSON对象，防止反序列化攻击和数据污染
     *
     * @param credObj 凭据JSON对象
     * @throws ValidationException 如果验证失败
     */
    public static void validateCredentialJson(JSONObject credObj) throws ValidationException {
        if (credObj == null) {
            throw new ValidationException("Credential data is null");
        }

        // 检查凭据数量限制
        if (credObj.size() > ALLOWED_FIELDS.size()) {
            throw new ValidationException("Credential object contains too many fields");
        }

        // 验证type字段是否在白名单中
        String type = credObj.optString("type", null);
        if (type != null && !ALLOWED_CREDENTIAL_TYPES.contains(type)) {
            throw new ValidationException("Unsupported credential type: " + type);
        }

        // 验证所有字段名是否在白名单中
        for (Object key : credObj.keySet()) {
            if (!(key instanceof String)) {
                throw new ValidationException("Invalid field key type");
            }
            if (!ALLOWED_FIELDS.contains((String) key)) {
                throw new ValidationException("Unknown field in credential data: " + key);
            }
        }

        // 验证各字段长度
        validateId(credObj.optString("id", null), false);
        validateDescription(credObj.optString("description", null));
        String username = credObj.optString("username", null);
        if (username != null && username.length() > MAX_USERNAME_LENGTH) {
            throw new ValidationException("Username exceeds maximum length");
        }
        String secret = credObj.optString("secret", null);
        if (secret != null && secret.length() > MAX_SECRET_LENGTH) {
            throw new ValidationException("Secret exceeds maximum length");
        }
        String password = credObj.optString("password", null);
        if (password != null && password.length() > MAX_PASSWORD_LENGTH) {
            throw new ValidationException("Password exceeds maximum length");
        }
        String privateKey = credObj.optString("privateKey", null);
        if (privateKey != null && privateKey.length() > MAX_PRIVATE_KEY_LENGTH) {
            throw new ValidationException("Private key exceeds maximum length");
        }
        String fileName = credObj.optString("fileName", null);
        if (fileName != null && fileName.length() > 255) {
            throw new ValidationException("File name exceeds maximum length");
        }
        String fileContent = credObj.optString("fileContent", null);
        if (fileContent != null && fileContent.length() > MAX_SECRET_LENGTH) {
            throw new ValidationException("File content exceeds maximum length");
        }
        String keyStoreBytes = credObj.optString("keyStoreBytes", null);
        if (keyStoreBytes != null && keyStoreBytes.length() > MAX_SECRET_LENGTH) {
            throw new ValidationException("KeyStore bytes exceed maximum length");
        }
        String keyStorePassword = credObj.optString("keyStorePassword", null);
        if (keyStorePassword != null && keyStorePassword.length() > MAX_PASSWORD_LENGTH) {
            throw new ValidationException("KeyStore password exceeds maximum length");
        }
    }
}
