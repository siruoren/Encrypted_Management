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

import com.cloudbees.hudson.plugins.folder.Folder;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

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

        // 解析选中的凭据ID
        String selectedIdsParam = req.getParameter("selectedIds");
        java.util.Set<String> selectedIds = null;
        if (selectedIdsParam != null && !selectedIdsParam.isEmpty()) {
            selectedIds = new java.util.HashSet<>(java.util.Arrays.asList(selectedIdsParam.split(",")));
        }

        try {
            String encryptedData = CredentialBackupService.exportCredentials((ItemGroup<?>) getJenkinsInstance(), password, selectedIds);
            AuditLogger.logExport("system", "exported system credentials" + (selectedIds != null ? " (selected: " + selectedIds.size() + ")" : ""));

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
            // 解析选中的凭据ID
            String selectedIdsParam = req.getParameter("selectedIds");
            java.util.Set<String> selectedIds = null;
            if (selectedIdsParam != null && !selectedIdsParam.isEmpty()) {
                selectedIds = new java.util.HashSet<>(java.util.Arrays.asList(selectedIdsParam.split(",")));
            }

            String encryptedData = CredentialBackupService.exportCredentials((ItemGroup<?>) getJenkinsInstance(), password, selectedIds);
            AuditLogger.logExport("system", "exported system credentials as file" + (selectedIds != null ? " (selected: " + selectedIds.size() + ")" : ""));

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
        String selectedIndicesParam = req.getParameter("selectedIndices");

        if (password == null || password.isEmpty()) {
            return errorResponse("Decryption password is required");
        }
        if (encryptedData == null || encryptedData.isEmpty()) {
            return errorResponse("Encrypted data is required");
        }

        boolean overwrite = "true".equals(overwriteParam);
        java.util.Set<Integer> selectedIndices = ImportService.parseSelectedIndices(selectedIndicesParam);

        try {
            ImportResult importResult = ImportService.importFromEncrypted(
                    getJenkinsInstance(), encryptedData, password, overwrite, selectedIndices);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult.toJson());
            result.put("message", importResult.getSummaryMessage());
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import system credentials", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    /**
     * API: 解析加密备份数据，返回凭据列表（不实际导入）
     * 用于导入前预览凭据列表，让用户选择要导入的凭据
     */
    @RequirePOST
    public HttpResponse doParseImportData(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        String encryptedData = req.getParameter("data");

        if (password == null || password.isEmpty()) {
            return errorResponse("Decryption password is required");
        }
        if (encryptedData == null || encryptedData.isEmpty()) {
            return errorResponse("Encrypted data is required");
        }

        try {
            String plainJson = CredentialBackupService.decryptData(encryptedData, password);
            JSONObject importObj = JSONObject.fromObject(plainJson);

            // 返回凭据列表（隐藏敏感信息）
            net.sf.json.JSONArray credentials = importObj.optJSONArray("credentials");
            net.sf.json.JSONArray previewList = new net.sf.json.JSONArray();
            if (credentials != null) {
                for (int i = 0; i < credentials.size(); i++) {
                    JSONObject cred = credentials.getJSONObject(i);
                    JSONObject preview = new JSONObject();
                    preview.put("index", i);
                    preview.put("id", cred.optString("id", ""));
                    preview.put("description", cred.optString("description", ""));
                    preview.put("type", cred.optString("type", ""));
                    preview.put("scope", cred.optString("scope", ""));
                    if (cred.has("username")) {
                        preview.put("username", cred.getString("username"));
                    }
                    previewList.add(preview);
                }
            }

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("folder", importObj.optString("folder", ""));
            result.put("exportTime", importObj.optString("exportTime", ""));
            result.put("count", previewList.size());
            result.put("credentials", previewList);
            result.put("encryptedData", encryptedData); // 回传加密数据，供后续导入使用
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to parse import data", e);
            return errorResponse("Failed to parse data: " + e.getMessage());
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
            ImportResult importResult = ImportService.importFromEncrypted(
                    getJenkinsInstance(), encryptedData.trim(), password, overwrite, null);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult.toJson());
            result.put("message", importResult.getSummaryMessage());
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import system credentials from file", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    /**
     * API: 从外部存储导入系统级凭据
     */
    @RequirePOST
    public HttpResponse doImportFromExternal(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String overwriteParam = req.getParameter("overwrite");
        boolean overwrite = "true".equals(overwriteParam);

        try {
            ImportResult importResult = ImportService.importFromExternal(getJenkinsInstance(), overwrite);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult.toJson());
            result.put("message", importResult.getSummaryMessage());
            return jsonResult(result);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import system credentials from external storage", e);
            return errorResponse("Failed to import credentials from external storage: " + e.getMessage());
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

        // 启用外部存储时必须设置加密密码
        if (enabled && (encryptionPassword == null || encryptionPassword.isEmpty())
                && (manager.getEncryptionPassword() == null || manager.getEncryptionPassword().isEmpty())) {
            return errorResponse("Encryption password is required when enabling external storage");
        }

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

        // 收集所有目录任务及其凭据（快照）
        final java.util.LinkedHashMap<String, List<StandardCredentials>> allFolderCreds = collectAllFolderCredentials();

        getAsyncExecutor().submit(new Runnable() {
            @Override
            public void run() {
                try {
                    ExternalStorage storage = manager.getStorage();
                    int totalSynced = 0;

                    for (Map.Entry<String, List<StandardCredentials>> entry : allFolderCreds.entrySet()) {
                        String folderName = entry.getKey();
                        List<StandardCredentials> creds = entry.getValue();

                        try {
                            net.sf.json.JSONArray credentialsArray = new net.sf.json.JSONArray();
                            for (StandardCredentials c : creds) {
                                try {
                                    JSONObject credData = serializeCredential(c);
                                    credentialsArray.add(credData);
                                } catch (Exception e) {
                                    LOGGER.log(Level.WARNING, "Failed to serialize credential: " + c.getId(), e);
                                }
                            }

                            JSONObject allData = new JSONObject();
                            allData.put("version", "1.0");
                            allData.put("folder", folderName);
                            allData.put("exportTime", java.time.LocalDateTime.now().toString());
                            allData.put("count", credentialsArray.size());
                            allData.put("credentials", credentialsArray);

                            storage.saveAllCredentials(folderName, allData);
                            totalSynced += credentialsArray.size();
                        } catch (Exception e) {
                            LOGGER.log(Level.WARNING, "Failed to sync credentials for folder: " + folderName, e);
                        }
                    }

                    AuditLogger.log("system", "SYNC_TO_EXTERNAL", "*", "*", "synced " + totalSynced + " credentials across " + allFolderCreds.size() + " folders");
                    LOGGER.info("Async sync completed: " + totalSynced + " credentials synced across " + allFolderCreds.size() + " folders");
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to sync all credentials to external storage", e);
                }
            }
        });

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "Sync started in background for " + allFolderCreds.size() + " folders");
        result.put("folderCount", allFolderCreds.size());
        return jsonResult(result);
    }

    /**
     * API: 导出所有目录任务的凭据为加密ZIP包
     * ZIP包结构与Jenkins目录任务路径保持一致
     * 例如: dev/team.enc, jenkins_root.enc
     */
    @RequirePOST
    public HttpResponse doExportAllAsZip(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        if (password == null || password.isEmpty()) {
            return errorResponse("Encryption password is required");
        }
        if (password.length() < 8) {
            return errorResponse("Password must be at least 8 characters");
        }

        try {
            java.util.LinkedHashMap<String, List<StandardCredentials>> allFolderCreds = collectAllFolderCredentials();

            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            try (ZipOutputStream zos = new ZipOutputStream(baos)) {
                for (Map.Entry<String, List<StandardCredentials>> entry : allFolderCreds.entrySet()) {
                    String folderName = entry.getKey();
                    List<StandardCredentials> creds = entry.getValue();

                    net.sf.json.JSONArray credentialsArray = new net.sf.json.JSONArray();
                    for (StandardCredentials c : creds) {
                        try {
                            credentialsArray.add(serializeCredential(c));
                        } catch (Exception e) {
                            LOGGER.log(Level.WARNING, "Failed to serialize credential: " + c.getId(), e);
                        }
                    }

                    JSONObject allData = new JSONObject();
                    allData.put("version", "1.0");
                    allData.put("folder", folderName);
                    allData.put("exportTime", java.time.LocalDateTime.now().toString());
                    allData.put("count", credentialsArray.size());
                    allData.put("credentials", credentialsArray);

                    // 加密凭据数据
                    String encryptedData = CredentialBackupService.encryptData(allData.toString(), password);

                    // ZIP内路径与额外存储路径一致：fullName/taskName.enc
                    String zipEntryName;
                    if ("system".equals(folderName)) {
                        zipEntryName = "jenkins_root.enc";
                    } else {
                        int lastSlash = folderName.lastIndexOf('/');
                        String taskName = lastSlash > 0 ? folderName.substring(lastSlash + 1) : folderName;
                        zipEntryName = folderName + "/" + taskName + ".enc";
                    }

                    ZipEntry ze = new ZipEntry(zipEntryName);
                    zos.putNextEntry(ze);
                    zos.write(encryptedData.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    zos.closeEntry();
                }
            }

            final byte[] zipBytes = baos.toByteArray();
            final String filename = "jenkins-all-credentials-"
                    + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
                    + ".zip";

            AuditLogger.log("system", "EXPORT_ALL_ZIP", "*", "*", "exported " + allFolderCreds.size() + " folders as ZIP");

            return new HttpResponse() {
                @Override
                public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                    rsp.setContentType("application/octet-stream");
                    rsp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
                    rsp.getOutputStream().write(zipBytes);
                }
            };
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to export all credentials as ZIP", e);
            return errorResponse("Failed to export credentials: " + e.getMessage());
        }
    }

    /**
     * API: 解析加密ZIP包，返回所有凭据列表（不实际导入）
     * 用于导入前预览凭据列表，让用户选择要导入的凭据
     */
    @RequirePOST
    public HttpResponse doParseZipData(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        String encryptedZipData = req.getParameter("data");

        if (password == null || password.isEmpty()) {
            return errorResponse("Decryption password is required");
        }
        if (encryptedZipData == null || encryptedZipData.isEmpty()) {
            return errorResponse("ZIP data is required");
        }

        try {
            byte[] zipBytes = java.util.Base64.getDecoder().decode(encryptedZipData);
            java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(zipBytes);

            net.sf.json.JSONArray allPreview = new net.sf.json.JSONArray();

            try (ZipInputStream zis = new ZipInputStream(bais)) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    try {
                        java.io.ByteArrayOutputStream entryBaos = new java.io.ByteArrayOutputStream();
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            entryBaos.write(buffer, 0, len);
                        }
                        String encryptedContent = entryBaos.toString(java.nio.charset.StandardCharsets.UTF_8.name());

                        String decryptedJson = CredentialBackupService.decryptData(encryptedContent, password);
                        JSONObject importObj = JSONObject.fromObject(decryptedJson);

                        String entryPath = entry.getName();
                        String folderName;
                        if ("jenkins_root.enc".equals(entryPath)) {
                            folderName = "system";
                        } else {
                            // 新路径格式: test/test.enc → folderName="test", dev/team/team.enc → folderName="dev/team"
                            // .enc 文件所在目录的路径就是 folderName
                            int lastSlash = entryPath.lastIndexOf('/');
                            if (lastSlash > 0) {
                                folderName = entryPath.substring(0, lastSlash);
                            } else {
                                // 兼容旧格式: test.enc → folderName="test"
                                folderName = entryPath;
                                if (folderName.endsWith(".enc")) {
                                    folderName = folderName.substring(0, folderName.length() - 4);
                                }
                            }
                        }

                        net.sf.json.JSONArray credentials = importObj.optJSONArray("credentials");
                        if (credentials != null) {
                            for (int i = 0; i < credentials.size(); i++) {
                                JSONObject cred = credentials.getJSONObject(i);
                                JSONObject preview = new JSONObject();
                                preview.put("folderEntry", entryPath);
                                preview.put("folderName", folderName);
                                preview.put("index", i);
                                preview.put("id", cred.optString("id", ""));
                                preview.put("description", cred.optString("description", ""));
                                preview.put("type", cred.optString("type", ""));
                                preview.put("scope", cred.optString("scope", ""));
                                if (cred.has("username")) {
                                    preview.put("username", cred.getString("username"));
                                }
                                allPreview.add(preview);
                            }
                        }
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Failed to parse ZIP entry: " + entry.getName(), e);
                    }
                    zis.closeEntry();
                }
            }

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("count", allPreview.size());
            result.put("credentials", allPreview);
            return jsonResult(result);
        } catch (Exception e) {
            if (e.getCause() instanceof javax.crypto.AEADBadTagException) {
                return errorResponse("Decryption failed: wrong password or corrupted data");
            }
            LOGGER.log(Level.SEVERE, "Failed to parse ZIP data", e);
            return errorResponse("Failed to parse data: " + e.getMessage());
        }
    }

    /**
     * API: 从加密ZIP包导入所有目录任务的凭据（并发导入）
     */
    @RequirePOST
    public HttpResponse doImportAllFromZip(StaplerRequest req, StaplerResponse rsp) throws IOException {
        getJenkinsInstance().checkPermission(Jenkins.ADMINISTER);

        String password = req.getParameter("password");
        String encryptedZipData = req.getParameter("data");
        String overwriteParam = req.getParameter("overwrite");
        String selectedEntriesParam = req.getParameter("selectedEntries");

        if (password == null || password.isEmpty()) {
            return errorResponse("Decryption password is required");
        }
        if (encryptedZipData == null || encryptedZipData.isEmpty()) {
            return errorResponse("ZIP data is required");
        }

        boolean overwrite = "true".equals(overwriteParam);
        java.util.Set<String> selectedEntries = ImportService.parseSelectedEntries(selectedEntriesParam);

        try {
            ImportResult importResult = ImportService.importFromZip(encryptedZipData, password, overwrite, selectedEntries);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult.toJson());
            result.put("message", importResult.getSummaryMessage());
            return jsonResult(result);
        } catch (Exception e) {
            if (e.getCause() instanceof javax.crypto.AEADBadTagException) {
                return errorResponse("Decryption failed: wrong password or corrupted data");
            }
            LOGGER.log(Level.SEVERE, "Failed to import credentials from ZIP", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    // ==================== 辅助方法 ====================

    /**
     * 收集所有目录任务及其凭据（仅自身存储的凭据，不包含继承的）
     * 包括系统级凭据和所有Folder的凭据
     */
    private java.util.LinkedHashMap<String, List<StandardCredentials>> collectAllFolderCredentials() {
        java.util.LinkedHashMap<String, List<StandardCredentials>> result = new java.util.LinkedHashMap<>();

        // 系统级凭据
        List<StandardCredentials> systemCreds = getStoreCredentials(getJenkinsInstance());
        if (!systemCreds.isEmpty()) {
            result.put("system", systemCreds);
        }

        // 所有Folder的凭据
        for (Folder folder : Jenkins.get().getAllItems(Folder.class)) {
            List<StandardCredentials> folderCreds = getStoreCredentials(folder);
            if (!folderCreds.isEmpty()) {
                result.put(folder.getFullName(), folderCreds);
            }
        }

        return result;
    }

    /**
     * 获取指定ItemGroup自身凭据存储中的所有凭据（不包含继承的）
     */
    private List<StandardCredentials> getStoreCredentials(ItemGroup<?> itemGroup) {
        List<StandardCredentials> creds = new ArrayList<>();
        CredentialsStore store = null;
        for (CredentialsStore s : CredentialsProvider.lookupStores(itemGroup)) {
            if (s.getContext() == itemGroup) {
                store = s;
                break;
            }
        }
        if (store != null) {
            for (Domain domain : store.getDomains()) {
                for (com.cloudbees.plugins.credentials.Credentials c : store.getCredentials(domain)) {
                    if (c instanceof StandardCredentials) {
                        creds.add((StandardCredentials) c);
                    }
                }
            }
        }
        return creds;
    }

    /**
     * 序列化凭据为JSON对象
     */
    private JSONObject serializeCredential(StandardCredentials c) {
        JSONObject credData = new JSONObject();
        credData.put("id", c.getId());
        credData.put("description", c.getDescription());
        credData.put("scope", c.getScope().name());
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
        return credData;
    }

    /**
     * 获取凭据类型名称
     */
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
