package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import hudson.model.ItemGroup;
import hudson.security.ACL;
import hudson.security.ACLContext;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 统一导入服务
 * <p>
 * 集中管理所有导入逻辑，包括：
 * - 单文件夹凭据导入（加密文本/文件）
 * - ZIP全量导入
 * - 外部存储导入
 * <p>
 * 使用线程池并发导入，提升批量导入速度
 * 返回ImportResult详细结果，包含每条凭据的导入状态
 */
public class ImportService {
    private static final Logger LOGGER = Logger.getLogger(ImportService.class.getName());

    private ImportService() {}

    /**
     * 从加密数据导入凭据到指定ItemGroup（支持选择索引）
     *
     * @param itemGroup       目标ItemGroup
     * @param encryptedData   加密的Base64字符串
     * @param password        解密密码
     * @param overwrite       是否覆盖已存在
     * @param selectedIndices 选中的凭据索引，null表示全部
     * @return ImportResult 详细导入结果
     */
    public static ImportResult importFromEncrypted(ItemGroup<?> itemGroup, String encryptedData,
                                                   String password, boolean overwrite,
                                                   Set<Integer> selectedIndices) throws Exception {
        String plainJson = CredentialBackupService.decryptData(encryptedData, password);
        JSONObject importObj = JSONObject.fromObject(plainJson);
        return importFromJson(itemGroup, importObj, overwrite, selectedIndices, null);
    }

    /**
     * 从JSON对象导入凭据到指定ItemGroup
     *
     * @param itemGroup       目标ItemGroup
     * @param importObj       已解密的JSON对象
     * @param overwrite       是否覆盖已存在
     * @param selectedIndices 选中的凭据索引，null表示全部
     * @param userName        审计日志用户名（线程池场景下传入实际登录用户）
     * @return ImportResult 详细导入结果
     */
    public static ImportResult importFromJson(ItemGroup<?> itemGroup, JSONObject importObj,
                                              boolean overwrite, Set<Integer> selectedIndices,
                                              String userName) throws Exception {
        JSONArray credentialsArray = importObj.getJSONArray("credentials");

        // 安全检查：凭据数量限制
        if (credentialsArray.size() > CredentialService.MAX_CREDENTIALS_PER_IMPORT) {
            throw new SecurityException("Too many credentials in import data (max "
                    + CredentialService.MAX_CREDENTIALS_PER_IMPORT + ")");
        }

        String sourceFolder = importObj.optString("folder", "unknown");
        String folderName = itemGroup instanceof hudson.model.Item
                ? ((hudson.model.Item) itemGroup).getFullName() : "system";

        CredentialsStore store = findStore(itemGroup);
        if (store == null) {
            throw new IOException("No credentials store found for: " + folderName);
        }

        ImportResult result = new ImportResult(folderName);

        for (int i = 0; i < credentialsArray.size(); i++) {
            if (selectedIndices != null && !selectedIndices.contains(i)) {
                continue;
            }
            JSONObject credObj = credentialsArray.getJSONObject(i);

            // JSON Schema 验证：字段白名单和长度校验
            try {
                CredentialService.validateCredentialJson(credObj);
            } catch (CredentialService.ValidationException ve) {
                String id = credObj.optString("id", "unknown");
                result.record(ImportResult.Status.FAILED, id, "", "UNKNOWN", ve.getMessage());
                continue;
            }

            String id = credObj.optString("id", null);
            String description = credObj.optString("description", "");
            String type = credObj.optString("type", "UNKNOWN");

            try {
                StandardCredentials existing = findCredentialById(itemGroup, id);

                if (existing != null && !overwrite) {
                    result.record(ImportResult.Status.SKIPPED, id, description, type,
                            "Credential already exists");
                    continue;
                }

                StandardCredentials newCred = CredentialBackupService.buildCredential(credObj, type, id, description);

                if (existing != null) {
                    store.updateCredentials(Domain.global(), existing, newCred);
                    result.record(ImportResult.Status.UPDATED, id, description, type,
                            "Overwritten existing credential");
                } else {
                    store.addCredentials(Domain.global(), newCred);
                    result.record(ImportResult.Status.IMPORTED, id, description, type,
                            "New credential created");
                }
            } catch (Exception e) {
                result.record(ImportResult.Status.FAILED, id, description, type,
                        e.getMessage());
                LOGGER.log(Level.WARNING, "Failed to import credential: " + id, e);
            }
        }

        AuditLogger.logImport(folderName, result.getSummaryMessage(), userName);
        return result;
    }

    /**
     * 从ZIP包导入所有凭据（并发处理各ZIP条目）
     *
     * @param zipBase64Data   ZIP的Base64编码数据
     * @param password        解密密码
     * @param overwrite       是否覆盖已存在
     * @param selectedEntries 选中的条目集合（格式: "entryPath:index"），null表示全部
     * @param auth            当前请求的Authentication，用于线程池中权限上下文和审计日志
     * @return ImportResult 合并后的导入结果
     */
    public static ImportResult importFromZip(String zipBase64Data, String password,
                                             boolean overwrite, Set<String> selectedEntries,
                                             Authentication auth) throws Exception {
        byte[] zipBytes = java.util.Base64.getDecoder().decode(zipBase64Data);

        // 安全检查：ZIP文件大小限制
        if (zipBytes.length > CredentialService.MAX_ZIP_SIZE_BYTES) {
            throw new SecurityException("ZIP file exceeds maximum allowed size ("
                    + CredentialService.MAX_ZIP_SIZE_BYTES / (1024 * 1024) + "MB)");
        }

        // 先解析所有ZIP条目
        List<ZipEntryData> entries = parseZipEntries(zipBytes, password);

        // 安全检查：ZIP条目数量限制
        if (entries.size() > CredentialService.MAX_ZIP_ENTRIES) {
            throw new SecurityException("ZIP contains too many entries (max "
                    + CredentialService.MAX_ZIP_ENTRIES + ")");
        }

        ImportResult mergedResult = new ImportResult("all");

        // 使用线程池并发导入各条目
        ExecutorService executor = ThreadPoolManager.getInstance().getExecutor();
        List<Future<ImportResult>> futures = new ArrayList<>();

        // 使用调用线程传入的Authentication，确保工作线程拥有正确的权限上下文和审计用户
        final Authentication userAuth = auth != null ? auth : Jenkins.get().getAuthentication();
        final String userName = userAuth.getName();

        for (ZipEntryData entryData : entries) {
            futures.add(executor.submit(new Callable<ImportResult>() {
                @Override
                public ImportResult call() throws Exception {
                    // 在线程池工作线程中使用实际登录用户的权限上下文
                    try (ACLContext ctx = ACL.as(userAuth)) {
                        return importZipEntry(entryData, overwrite, selectedEntries, userName);
                    }
                }
            }));
        }

        // 收集结果
        List<String> processedFolders = new ArrayList<>();
        for (int i = 0; i < futures.size(); i++) {
            try {
                ImportResult entryResult = futures.get(i).get();
                mergedResult.merge(entryResult);
                processedFolders.add(entries.get(i).entryPath);
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Failed to get import result for ZIP entry: "
                        + entries.get(i).entryPath, e);
                mergedResult.record(ImportResult.Status.FAILED, null, null, null,
                        "ZIP entry failed: " + entries.get(i).entryPath + " - " + e.getMessage());
            }
        }

        AuditLogger.logImport("system", "ZIP import: " + mergedResult.getSummaryMessage()
                + ", folders: " + processedFolders.size(), userName);
        return mergedResult;
    }

    /**
     * 从外部存储导入凭据
     */
    public static ImportResult importFromExternal(ItemGroup<?> itemGroup, boolean overwrite) throws Exception {
        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        if (!manager.isEnabled()) {
            throw new IOException("External storage is not enabled");
        }

        String folderName = itemGroup instanceof hudson.model.Item
                ? ((hudson.model.Item) itemGroup).getFullName() : "system";

        ExternalStorage storage = manager.getStorage();
        JSONObject externalData = storage.loadAllCredentials(folderName);

        if (externalData == null) {
            throw new IOException("No credentials found in external storage for: " + folderName);
        }

        ImportResult result = importFromJson(itemGroup, externalData, overwrite, null, null);
        AuditLogger.logImport(folderName, "imported from external: " + result.getSummaryMessage(), null);
        return result;
    }

    // ==================== 内部方法 ====================

    /** ZIP条目解析数据 */
    private static class ZipEntryData {
        String entryPath;
        String folderName;
        ItemGroup<?> targetItemGroup;
        JSONObject importObj;

        ZipEntryData(String entryPath, String folderName, ItemGroup<?> targetItemGroup, JSONObject importObj) {
            this.entryPath = entryPath;
            this.folderName = folderName;
            this.targetItemGroup = targetItemGroup;
            this.importObj = importObj;
        }
    }

    /** 解析ZIP包中所有条目 */
    private static List<ZipEntryData> parseZipEntries(byte[] zipBytes, String password) throws Exception {
        List<ZipEntryData> entries = new ArrayList<>();
        ByteArrayInputStream bais = new ByteArrayInputStream(zipBytes);

        try (ZipInputStream zis = new ZipInputStream(bais)) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                try {
                    // Zip Slip 防护：检查路径遍历攻击
                    String entryName = entry.getName();
                    if (entryName.contains("..") || entryName.startsWith("/") || entryName.startsWith("\\")) {
                        LOGGER.warning("Skipping ZIP entry with suspicious path: " + entryName);
                        zis.closeEntry();
                        continue;
                    }

                    ByteArrayOutputStream entryBaos = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = zis.read(buffer)) > 0) {
                        entryBaos.write(buffer, 0, len);
                    }
                    String encryptedContent = entryBaos.toString(StandardCharsets.UTF_8.name());
                    String decryptedJson = CredentialBackupService.decryptData(encryptedContent, password);
                    JSONObject importObj = JSONObject.fromObject(decryptedJson);

                    String entryPath = entry.getName();
                    String folderName = extractFolderName(entryPath);
                    ItemGroup<?> targetItemGroup = resolveTargetItemGroup(entryPath);

                    if (targetItemGroup == null) {
                        LOGGER.warning("Folder not found for ZIP entry: " + entryPath + ", skipping");
                        continue;
                    }

                    entries.add(new ZipEntryData(entryPath, folderName, targetItemGroup, importObj));
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to parse ZIP entry: " + entry.getName(), e);
                }
                zis.closeEntry();
            }
        }
        return entries;
    }

    /** 导入单个ZIP条目 */
    private static ImportResult importZipEntry(ZipEntryData entryData, boolean overwrite,
                                               Set<String> selectedEntries, String userName) throws Exception {
        // 计算该条目中选中的凭据索引
        Set<Integer> selectedIndices = null;
        if (selectedEntries != null) {
            selectedIndices = new HashSet<>();
            for (String sel : selectedEntries) {
                if (sel.startsWith(entryData.entryPath + ":")) {
                    try {
                        selectedIndices.add(Integer.parseInt(sel.substring(entryData.entryPath.length() + 1)));
                    } catch (NumberFormatException ignored) {}
                }
            }
        }

        return importFromJson(entryData.targetItemGroup, entryData.importObj, overwrite, selectedIndices, userName);
    }

    /** 从ZIP条目路径提取folderName */
    static String extractFolderName(String entryPath) {
        if ("jenkins_root.enc".equals(entryPath)) {
            return "system";
        }
        int lastSlash = entryPath.lastIndexOf('/');
        if (lastSlash > 0) {
            return entryPath.substring(0, lastSlash);
        }
        // 兼容旧格式: test.enc → test
        String name = entryPath;
        if (name.endsWith(".enc")) {
            name = name.substring(0, name.length() - 4);
        }
        return name;
    }

    /** 根据ZIP条目路径查找目标ItemGroup */
    private static ItemGroup<?> resolveTargetItemGroup(String entryPath) {
        if ("jenkins_root.enc".equals(entryPath)) {
            return Jenkins.get();
        }
        String folderFullName = extractFolderName(entryPath);
        if ("system".equals(folderFullName)) {
            return Jenkins.get();
        }
        for (Folder folder : Jenkins.get().getAllItems(Folder.class)) {
            if (folder.getFullName().equals(folderFullName)) {
                return folder;
            }
        }
        return null;
    }

    /** 查找ItemGroup的凭据存储 */
    private static CredentialsStore findStore(ItemGroup<?> itemGroup) {
        for (CredentialsStore s : CredentialsProvider.lookupStores(itemGroup)) {
            if (s.getContext() == itemGroup) {
                return s;
            }
        }
        return null;
    }

    /** 根据ID查找凭据 */
    private static StandardCredentials findCredentialById(ItemGroup<?> itemGroup, String id) {
        if (id == null || id.isEmpty()) return null;
        for (StandardCredentials c : getStoreCredentials(itemGroup)) {
            if (c.getId().equals(id)) {
                return c;
            }
        }
        return null;
    }

    /** 获取ItemGroup自身凭据存储中的凭据 */
    private static List<StandardCredentials> getStoreCredentials(ItemGroup<?> itemGroup) {
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

    // ==================== 参数解析工具方法 ====================

    /** 解析选中的凭据索引参数 */
    public static Set<Integer> parseSelectedIndices(String param) {
        if (param == null || param.isEmpty()) return null;
        Set<Integer> indices = new HashSet<>();
        for (String idx : param.split(",")) {
            try {
                indices.add(Integer.parseInt(idx.trim()));
            } catch (NumberFormatException ignored) {}
        }
        return indices.isEmpty() ? null : indices;
    }

    /** 解析ZIP导入选中的条目参数 */
    public static Set<String> parseSelectedEntries(String param) {
        if (param == null || param.isEmpty()) return null;
        Set<String> entries = new HashSet<>(Arrays.asList(param.split(",")));
        return entries.isEmpty() ? null : entries;
    }
}
