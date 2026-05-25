package com.siruoren.encrypted_management;

import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.RootAction;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Jenkins根目录系统级凭据管理Action
 * 仅管理员可见，管理Jenkins系统级凭据
 * 使用RootAction直接注册到Jenkins根侧边栏
 */
@Extension
public class SystemCredentialsAction implements RootAction {
    private static final Logger LOGGER = Logger.getLogger(SystemCredentialsAction.class.getName());

    private static ExecutorService getAsyncExecutor() {
        return ThreadPoolManager.getInstance().getExecutor();
    }

    private Jenkins getJenkinsInstance() {
        return Jenkins.get();
    }

    @Override
    public String getIconFileName() {
        return getJenkinsInstance().hasPermission(Jenkins.ADMINISTER) ? "symbol-credentials plugin-encrypted-management" : null;
    }

    @Override
    public String getDisplayName() {
        return getJenkinsInstance().hasPermission(Jenkins.ADMINISTER) ? Messages.SystemCredentialsAction_DisplayName() : null;
    }

    @Override
    public String getUrlName() {
        return getJenkinsInstance().hasPermission(Jenkins.ADMINISTER) ? "System_Credentials_Management" : null;
    }

    /**
     * 检查当前用户是否是管理员
     */
    public boolean hasPermission() {
        return getJenkinsInstance().hasPermission(Jenkins.ADMINISTER);
    }

    /**
     * API文档页面路由
     */
    public void doApiDoc(StaplerRequest req, StaplerResponse rsp) throws IOException, javax.servlet.ServletException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);
        req.getView(this, "api-doc").forward(req, rsp);
    }

    public Jenkins getJenkins() {
        return getJenkinsInstance();
    }

    /**
     * 获取上下文对象（兼容视图中的 it.folder 引用）
     * Jenkins 实例同样有 displayName、url、fullName 属性
     */
    public Object getContext() {
        return getJenkinsInstance();
    }

    /**
     * 获取凭据管理的URL路径
     */
    public String getActionUrl() {
        return "System_Credentials_Management";
    }

    public String getFolderFullName() {
        return "system";
    }

    /**
     * 获取Jenkins系统凭据存储
     */
    private CredentialsStore getSystemStore() {
        for (CredentialsStore store : CredentialsProvider.lookupStores(getJenkinsInstance())) {
            if (store.getContext() == getJenkinsInstance()) {
                return store;
            }
        }
        return null;
    }

    /**
     * 根据ID查找系统凭据
     */
    private StandardCredentials findCredentialById(String id) {
        List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) getJenkinsInstance(), null, Collections.emptyList());
        for (StandardCredentials c : creds) {
            if (c.getId().equals(id)) {
                return c;
            }
        }
        return null;
    }

    /**
     * API: 以JSON格式返回系统级所有凭据
     */
    public HttpResponse doListCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        JSONArray arr = new JSONArray();
        List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) getJenkinsInstance(), null, Collections.emptyList());

        for (StandardCredentials c : creds) {
            JSONObject obj = new JSONObject();
            obj.put("id", c.getId());
            obj.put("description", c.getDescription() != null ? c.getDescription() : "");
            obj.put("type", getCredentialsTypeName(c));
            obj.put("typeKey", getCredentialsTypeKey(c));

            if (c instanceof UsernamePasswordCredentials) {
                obj.put("username", ((UsernamePasswordCredentials) c).getUsername());
            } else if (c instanceof BasicSSHUserPrivateKey) {
                obj.put("username", ((BasicSSHUserPrivateKey) c).getUsername());
            }

            arr.add(obj);
        }

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("credentials", arr);
        result.put("folder", "system");
        result.put("count", creds.size());

        return jsonResult(result);
    }

    /**
     * API: 解密指定凭据的值
     */
    @RequirePOST
    public HttpResponse doDecryptCredential(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        StandardCredentials c = findCredentialById(id);
        if (c == null) {
            return errorResponse("Credential not found: " + id);
        }

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("id", id);
        result.put("type", getCredentialsTypeName(c));
        result.put("typeKey", getCredentialsTypeKey(c));

        if (c instanceof UsernamePasswordCredentials) {
            UsernamePasswordCredentials upc = (UsernamePasswordCredentials) c;
            result.put("username", upc.getUsername());
            result.put("password", Secret.toString(upc.getPassword()));
        } else if (c instanceof StringCredentials) {
            result.put("secret", Secret.toString(((StringCredentials) c).getSecret()));
        } else if (c instanceof BasicSSHUserPrivateKey) {
            BasicSSHUserPrivateKey ssh = (BasicSSHUserPrivateKey) c;
            result.put("username", ssh.getUsername());
            result.put("passphrase", Secret.toString(ssh.getPassphrase()));
            result.put("privateKey", ssh.getPrivateKey());
            String publicKey = EncryptedManagementAction.derivePublicKey(ssh.getPrivateKey(), ssh.getPassphrase());
            if (publicKey != null && !publicKey.isEmpty()) {
                result.put("publicKey", publicKey);
            }
        }

        AuditLogger.logRead("system", id, getCredentialsTypeKey(c));
        return jsonResult(result);
    }

    /**
     * API: 创建Secret Text凭据
     */
    @RequirePOST
    public HttpResponse doCreateSecretText(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String secret = req.getParameter("secret");

        if (secret == null || secret.trim().isEmpty()) {
            return errorResponse("Secret value is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            StringCredentialsImpl credential = new StringCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    Secret.fromString(secret));

            store.addCredentials(Domain.global(), credential);
            AuditLogger.logCreate("system", credential.getId(), "SECRET_TEXT");
            return successResponse("Secret text credential created successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create secret text credential", e);
            return errorResponse("Failed to create credential: " + e.getMessage());
        }
    }

    /**
     * API: 创建Username/Password凭据
     */
    @RequirePOST
    public HttpResponse doCreateUsernamePassword(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        if (username == null || username.trim().isEmpty()) {
            return errorResponse("Username is required");
        }
        if (password == null || password.trim().isEmpty()) {
            return errorResponse("Password is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            UsernamePasswordCredentialsImpl credential = new UsernamePasswordCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    username,
                    password);

            store.addCredentials(Domain.global(), credential);
            AuditLogger.logCreate("system", credential.getId(), "USERNAME_PASSWORD");
            return successResponse("Username/Password credential created successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create username/password credential", e);
            return errorResponse("Failed to create credential: " + e.getMessage());
        }
    }

    /**
     * API: 创建SSH Username with private key凭据
     */
    @RequirePOST
    public HttpResponse doCreateSSHKey(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String passphrase = req.getParameter("passphrase");
        String privateKey = req.getParameter("privateKey");

        if (username == null || username.trim().isEmpty()) {
            return errorResponse("Username is required");
        }
        if (privateKey == null || privateKey.trim().isEmpty()) {
            return errorResponse("Private key is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            BasicSSHUserPrivateKey.DirectEntryPrivateKeySource source =
                    new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(privateKey);

            BasicSSHUserPrivateKey credential = new BasicSSHUserPrivateKey(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    username,
                    source,
                    passphrase != null ? passphrase : "",
                    description);

            store.addCredentials(Domain.global(), credential);
            AuditLogger.logCreate("system", credential.getId(), "SSH_KEY");
            return successResponse("SSH credential created successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create SSH credential", e);
            return errorResponse("Failed to create credential: " + e.getMessage());
        }
    }

    /**
     * API: 更新Secret Text凭据
     */
    @RequirePOST
    public HttpResponse doUpdateSecretText(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String secret = req.getParameter("secret");

        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            StandardCredentials existing = findCredentialById(id);
            if (existing == null) {
                return errorResponse("Credential not found: " + id);
            }
            if (!(existing instanceof StringCredentials)) {
                return errorResponse("Credential is not a Secret Text type");
            }

            StringCredentialsImpl updated = new StringCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    id,
                    description != null ? description : existing.getDescription(),
                    Secret.fromString(secret != null ? secret : Secret.toString(((StringCredentials) existing).getSecret())));

            store.updateCredentials(Domain.global(), existing, updated);
            AuditLogger.logUpdate("system", id, "SECRET_TEXT");
            return successResponse("Secret text credential updated successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to update secret text credential", e);
            return errorResponse("Failed to update credential: " + e.getMessage());
        }
    }

    /**
     * API: 更新Username/Password凭据
     */
    @RequirePOST
    public HttpResponse doUpdateUsernamePassword(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            StandardCredentials existing = findCredentialById(id);
            if (existing == null) {
                return errorResponse("Credential not found: " + id);
            }
            if (!(existing instanceof UsernamePasswordCredentials)) {
                return errorResponse("Credential is not a Username/Password type");
            }

            UsernamePasswordCredentials oldCred = (UsernamePasswordCredentials) existing;
            UsernamePasswordCredentialsImpl updated = new UsernamePasswordCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    id,
                    description != null ? description : existing.getDescription(),
                    username != null ? username : oldCred.getUsername(),
                    password != null ? password : Secret.toString(oldCred.getPassword()));

            store.updateCredentials(Domain.global(), existing, updated);
            AuditLogger.logUpdate("system", id, "USERNAME_PASSWORD");
            return successResponse("Username/Password credential updated successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to update username/password credential", e);
            return errorResponse("Failed to update credential: " + e.getMessage());
        }
    }

    /**
     * API: 更新SSH凭据
     */
    @RequirePOST
    public HttpResponse doUpdateSSHKey(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String passphrase = req.getParameter("passphrase");
        String privateKey = req.getParameter("privateKey");

        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            StandardCredentials existing = findCredentialById(id);
            if (existing == null) {
                return errorResponse("Credential not found: " + id);
            }
            if (!(existing instanceof BasicSSHUserPrivateKey)) {
                return errorResponse("Credential is not an SSH Key type");
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

            store.updateCredentials(Domain.global(), existing, updated);
            AuditLogger.logUpdate("system", id, "SSH_KEY");
            return successResponse("SSH credential updated successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to update SSH credential", e);
            return errorResponse("Failed to update credential: " + e.getMessage());
        }
    }

    /**
     * API: 删除凭据
     */
    @RequirePOST
    public HttpResponse doDeleteCredential(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String id = req.getParameter("id");
        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getSystemStore();
        if (store == null) {
            return errorResponse("No system credentials store found");
        }

        try {
            StandardCredentials c = findCredentialById(id);
            if (c == null) {
                return errorResponse("Credential not found: " + id);
            }

            boolean removed = store.removeCredentials(Domain.global(), c);
            if (removed) {
                AuditLogger.logDelete("system", id, getCredentialsTypeKey(c));
                return successResponse("Credential deleted successfully");
            } else {
                return errorResponse("Failed to remove credential from store");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to delete credential", e);
            return errorResponse("Failed to delete credential: " + e.getMessage());
        }
    }

    /**
     * API: 生成SSH密钥对
     */
    @RequirePOST
    public HttpResponse doGenerateKeyPair(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);
        // 复用EncryptedManagementAction的密钥生成逻辑
        return EncryptedManagementAction.doGenerateKeyPairStatic(req.getParameter("passphrase"), "system");
    }

    // ==================== 审计日志 API ====================

    @RequirePOST
    public HttpResponse doAuditLog(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        int limit = 100;
        String limitParam = req.getParameter("limit");
        if (limitParam != null && !limitParam.isEmpty()) {
            try {
                limit = Math.min(Integer.parseInt(limitParam), 1000);
            } catch (NumberFormatException ignored) {}
        }

        java.util.List<String> logs = AuditLogger.readRecentLogs(limit);
        JSONArray logArray = new JSONArray();
        for (String line : logs) {
            logArray.add(line);
        }

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("logs", logArray);
        result.put("count", logs.size());
        result.put("maxRetentionDays", AuditLogger.getMaxLogFiles());
        return jsonResult(result);
    }

    @RequirePOST
    public HttpResponse doConfigureAuditLog(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String daysParam = req.getParameter("maxRetentionDays");
        if (daysParam != null && !daysParam.isEmpty()) {
            try {
                int days = Integer.parseInt(daysParam);
                if (days < 1) {
                    return errorResponse("Retention days must be at least 1");
                }
                AuditLogger.setMaxLogFiles(days);
                AuditLogger.log("system", "CONFIGURE_AUDIT", "*", "*", "maxRetentionDays=" + days);
                return successResponse("Audit log retention set to " + days + " days");
            } catch (NumberFormatException e) {
                return errorResponse("Invalid retention days value");
            }
        }
        return errorResponse("Missing maxRetentionDays parameter");
    }

    // ==================== 备份/导出/导入 API ====================

    @RequirePOST
    public HttpResponse doExportCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        if (password == null || password.isEmpty()) {
            return errorResponse("Encryption password is required");
        }
        if (password.length() < 8) {
            return errorResponse("Password must be at least 8 characters");
        }

        try {
            String encryptedData = CredentialBackupService.exportCredentials((ItemGroup<?>) getJenkinsInstance(), password);
            AuditLogger.logExport("system", "exported system credentials");

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("data", encryptedData);
            result.put("folder", "system");
            result.put("message", "System credentials exported successfully. Keep the encrypted data and password safe.");
            return jsonResult(result);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to export system credentials", e);
            return errorResponse("Failed to export credentials: " + e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doExportCredentialsFile(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        if (password == null || password.isEmpty()) {
            return errorResponse("Encryption password is required");
        }
        if (password.length() < 8) {
            return errorResponse("Password must be at least 8 characters");
        }

        try {
            String encryptedData = CredentialBackupService.exportCredentials((ItemGroup<?>) getJenkinsInstance(), password);
            AuditLogger.logExport("system", "exported system credentials as file");

            String filename = "credentials-backup-system-"
                    + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
                    + ".enc";

            return new HttpResponse() {
                @Override
                public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                    rsp.setContentType("application/octet-stream");
                    rsp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
                    rsp.getWriter().write(encryptedData);
                }
            };
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to export system credentials as file", e);
            return errorResponse("Failed to export credentials: " + e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doImportCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        String encryptedData = req.getParameter("data");
        String overwriteParam = req.getParameter("overwrite");

        if (password == null || password.isEmpty()) {
            return errorResponse("Decryption password is required");
        }
        if (encryptedData == null || encryptedData.isEmpty()) {
            return errorResponse("Encrypted data is required");
        }

        boolean overwrite = "true".equals(overwriteParam);

        try {
            JSONObject importResult = CredentialBackupService.importCredentials((ItemGroup<?>) getJenkinsInstance(), encryptedData, password, overwrite);
            AuditLogger.logImport("system", "imported: " + importResult.toString());

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult);
            result.put("message", "Credentials imported successfully");
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import system credentials", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    @RequirePOST
    public HttpResponse doImportCredentialsFile(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        String encryptedData = req.getParameter("data");
        String overwriteParam = req.getParameter("overwrite");

        if (password == null || password.isEmpty()) {
            return errorResponse("Decryption password is required");
        }
        if (encryptedData == null || encryptedData.isEmpty()) {
            return errorResponse("No backup data provided");
        }

        boolean overwrite = "true".equals(overwriteParam);

        try {
            JSONObject importResult = CredentialBackupService.importCredentials((ItemGroup<?>) getJenkinsInstance(), encryptedData.trim(), password, overwrite);
            AuditLogger.logImport("system", "imported from file: " + importResult.toString());

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult);
            result.put("message", "Credentials imported successfully from file");
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import system credentials from file", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    // ==================== 外部存储 API ====================

    @RequirePOST
    public HttpResponse doStorageStatus(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        JSONObject status = manager.getStatus();
        status.put("success", true);
        return jsonResult(status);
    }

    @RequirePOST
    public HttpResponse doConfigureStorage(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();

        String enabledStr = req.getParameter("enabled");
        String syncModeStr = req.getParameter("syncMode");
        String storagePath = req.getParameter("storagePath");
        String encryptionPassword = req.getParameter("encryptionPassword");

        boolean enabled = "true".equalsIgnoreCase(enabledStr);
        manager.setEnabled(enabled);

        if (syncModeStr != null) {
            try {
                ExternalStorageManager.SyncMode mode = ExternalStorageManager.SyncMode.valueOf(syncModeStr);
                manager.setSyncMode(mode);
            } catch (IllegalArgumentException e) {
                return errorResponse("Invalid sync mode: " + syncModeStr);
            }
        }

        if (storagePath != null && !storagePath.trim().isEmpty()) {
            manager.setStoragePath(storagePath.trim());
        }

        if (encryptionPassword != null && !encryptionPassword.isEmpty()) {
            manager.setEncryptionPassword(encryptionPassword);
        }

        String detail = "enabled=" + enabled + ", syncMode=" + syncModeStr
                + ", path=" + storagePath
                + ", encrypted=" + (encryptionPassword != null && !encryptionPassword.isEmpty());
        AuditLogger.log("system", "CONFIGURE_STORAGE", "*", "*", detail);
        return successResponse("External storage configuration saved");
    }

    @RequirePOST
    public HttpResponse doTestStorageConnection(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        boolean connected = manager.testConnection();

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("connected", connected);
        return jsonResult(result);
    }

    @RequirePOST
    public HttpResponse doSyncToExternal(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        if (!manager.isEnabled()) {
            return errorResponse("External storage is not enabled");
        }

        final List<StandardCredentials> creds = new ArrayList<>(CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) getJenkinsInstance(), null, Collections.emptyList()));
        final String folderName = "system";

        getAsyncExecutor().submit(new Runnable() {
            @Override
            public void run() {
                try {
                    ExternalStorage storage = manager.getStorage();
                    int synced = 0;
                    for (StandardCredentials c : creds) {
                        try {
                            JSONObject credData = new JSONObject();
                            credData.put("id", c.getId());
                            credData.put("description", c.getDescription());
                            credData.put("type", getCredentialsTypeKey(c));

                            if (c instanceof UsernamePasswordCredentials) {
                                UsernamePasswordCredentials upc = (UsernamePasswordCredentials) c;
                                credData.put("username", upc.getUsername());
                                credData.put("password", Secret.toString(upc.getPassword()));
                            } else if (c instanceof StringCredentials) {
                                credData.put("secret", Secret.toString(((StringCredentials) c).getSecret()));
                            } else if (c instanceof BasicSSHUserPrivateKey) {
                                BasicSSHUserPrivateKey ssh = (BasicSSHUserPrivateKey) c;
                                credData.put("username", ssh.getUsername());
                                credData.put("passphrase", Secret.toString(ssh.getPassphrase()));
                                credData.put("privateKey", ssh.getPrivateKey());
                            }

                            storage.saveCredential(folderName, c.getId(), credData);
                            synced++;
                        } catch (Exception e) {
                            LOGGER.log(Level.WARNING, "Failed to sync credential: " + c.getId(), e);
                        }
                    }

                    AuditLogger.log(folderName, "SYNC_TO_EXTERNAL", "*", "*", "synced " + synced + " credentials");
                    LOGGER.info("Async sync completed: " + synced + " system credentials synced");
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to sync system credentials to external storage", e);
                }
            }
        });

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "Sync started in background for " + creds.size() + " credentials");
        return jsonResult(result);
    }

    // ==================== 辅助方法 ====================

    private String getCredentialsTypeName(StandardCredentials c) {
        if (c instanceof UsernamePasswordCredentials) {
            return "Username with password";
        } else if (c instanceof BasicSSHUserPrivateKey) {
            return "SSH Username with private key";
        } else if (c instanceof StringCredentials) {
            return "Secret text";
        }
        return c.getClass().getSimpleName();
    }

    private String getCredentialsTypeKey(StandardCredentials c) {
        if (c instanceof UsernamePasswordCredentials) {
            return "USERNAME_PASSWORD";
        } else if (c instanceof BasicSSHUserPrivateKey) {
            return "SSH_KEY";
        } else if (c instanceof StringCredentials) {
            return "SECRET_TEXT";
        }
        return "OTHER";
    }

    private HttpResponse jsonResult(JSONObject json) {
        return new HttpResponse() {
            @Override
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                rsp.setContentType("application/json;charset=UTF-8");
                rsp.getWriter().write(json.toString());
            }
        };
    }

    private HttpResponse errorResponse(String message) {
        JSONObject result = new JSONObject();
        result.put("success", false);
        result.put("message", message);
        return jsonResult(result);
    }

    private HttpResponse successResponse(String message) {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", message);
        return jsonResult(result);
    }

}
