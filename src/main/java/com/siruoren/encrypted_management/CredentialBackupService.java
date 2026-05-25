package com.siruoren.encrypted_management;

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
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 凭据备份/导出/导入服务
 * 解决单点故障问题：凭据可导出为加密文件，独立于Jenkins Master存储
 * 使用AES-256-GCM加密，确保导出文件安全
 */
public class CredentialBackupService {
    private static final Logger LOGGER = Logger.getLogger(CredentialBackupService.class.getName());
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int AES_KEY_LENGTH = 256;
    private static final String BACKUP_VERSION = "1.0";

    private CredentialBackupService() {}

    /**
     * 导出当前文件夹的所有凭据为加密JSON
     * @param folder 文件夹
     * @param encryptionPassword 加密密码
     * @return 加密后的Base64字符串
     */
    public static String exportCredentials(ItemGroup<?> itemGroup, String encryptionPassword) throws Exception {
        return exportCredentials(itemGroup, encryptionPassword, null);
    }

    /**
     * 导出指定凭据ID的凭据为加密JSON
     * @param itemGroup 文件夹
     * @param encryptionPassword 加密密码
     * @param selectedIds 选中的凭据ID列表，为null时导出全部
     * @return 加密后的Base64字符串
     */
    public static String exportCredentials(ItemGroup<?> itemGroup, String encryptionPassword, java.util.Set<String> selectedIds) throws Exception {
        // 收集当前存储自身的凭据（不包含从父级继承的凭据）
        JSONArray credentialsArray = new JSONArray();
        List<StandardCredentials> creds = getStoreCredentials(itemGroup);

        for (StandardCredentials c : creds) {
            // 如果指定了选中ID列表，则只导出选中的凭据
            if (selectedIds != null && !selectedIds.contains(c.getId())) {
                continue;
            }

            JSONObject credObj = new JSONObject();
            credObj.put("id", c.getId());
            credObj.put("description", c.getDescription());
            credObj.put("scope", c.getScope().name());

            if (c instanceof UsernamePasswordCredentials) {
                UsernamePasswordCredentials upc = (UsernamePasswordCredentials) c;
                credObj.put("type", "USERNAME_PASSWORD");
                credObj.put("username", upc.getUsername());
                credObj.put("password", Secret.toString(upc.getPassword()));
            } else if (c instanceof StringCredentials) {
                StringCredentials sc = (StringCredentials) c;
                credObj.put("type", "SECRET_TEXT");
                credObj.put("secret", Secret.toString(sc.getSecret()));
            } else if (c instanceof BasicSSHUserPrivateKey) {
                BasicSSHUserPrivateKey ssh = (BasicSSHUserPrivateKey) c;
                credObj.put("type", "SSH_KEY");
                credObj.put("username", ssh.getUsername());
                credObj.put("passphrase", Secret.toString(ssh.getPassphrase()));
                credObj.put("privateKey", ssh.getPrivateKey());
            } else {
                continue; // 跳过不支持的类型
            }

            credentialsArray.add(credObj);
        }

        // 构建导出JSON
        String fullName = itemGroup instanceof hudson.model.Item ? ((hudson.model.Item) itemGroup).getFullName() : "";
        JSONObject exportObj = new JSONObject();
        exportObj.put("version", BACKUP_VERSION);
        exportObj.put("folder", fullName);
        exportObj.put("exportTime", java.time.LocalDateTime.now().toString());
        exportObj.put("count", credentialsArray.size());
        exportObj.put("credentials", credentialsArray);

        // 加密
        String plainJson = exportObj.toString();
        return encrypt(plainJson, encryptionPassword);
    }

    /**
     * 从加密JSON导入凭据到指定文件夹
     * @param folder 目标文件夹
     * @param encryptedData 加密的Base64字符串
     * @param encryptionPassword 解密密码
     * @param overwrite 是否覆盖已存在的凭据
     * @return 导入结果
     */
    public static JSONObject importCredentials(ItemGroup<?> itemGroup, String encryptedData,
                                                String encryptionPassword, boolean overwrite) throws Exception {
        return importCredentials(itemGroup, encryptedData, encryptionPassword, overwrite, null);
    }

    public static JSONObject importCredentials(ItemGroup<?> itemGroup, String encryptedData,
                                                String encryptionPassword, boolean overwrite,
                                                java.util.Set<Integer> selectedIndices) throws Exception {
        // 解密
        String plainJson = decrypt(encryptedData, encryptionPassword);
        JSONObject importObj = JSONObject.fromObject(plainJson);
        return importCredentialsFromJson(itemGroup, importObj, overwrite, selectedIndices);
    }

    public static JSONObject importCredentialsFromJson(ItemGroup<?> itemGroup, JSONObject importObj,
                                                       boolean overwrite) throws Exception {
        return importCredentialsFromJson(itemGroup, importObj, overwrite, null);
    }

    /**
     * 从已解密的JSON对象导入凭据到指定文件夹
     * 适用于外部存储导入（外部存储的JSON已由FileExternalStorage解密）
     * @param itemGroup 目标ItemGroup
     * @param importObj 已解密的JSON对象（包含credentials数组）
     * @param overwrite 是否覆盖已存在的凭据
     * @param selectedIndices 选中的凭据索引集合，为null时导入全部
     * @return 导入结果
     */
    public static JSONObject importCredentialsFromJson(ItemGroup<?> itemGroup, JSONObject importObj,
                                                       boolean overwrite, java.util.Set<Integer> selectedIndices) throws Exception {
        JSONArray credentialsArray = importObj.getJSONArray("credentials");
        String sourceFolder = importObj.optString("folder", "unknown");

        CredentialsStore store = null;
        for (CredentialsStore s : CredentialsProvider.lookupStores(itemGroup)) {
            if (s.getContext() == itemGroup) {
                store = s;
                break;
            }
        }
        if (store == null) {
            String name = itemGroup instanceof hudson.model.Item ? ((hudson.model.Item) itemGroup).getFullName() : "root";
            throw new IOException("No credentials store found for: " + name);
        }

        int imported = 0;
        int skipped = 0;
        int updated = 0;
        int failed = 0;

        for (int i = 0; i < credentialsArray.size(); i++) {
            // 如果指定了选中索引集合，则只导入选中的凭据
            if (selectedIndices != null && !selectedIndices.contains(i)) {
                continue;
            }
            JSONObject credObj = credentialsArray.getJSONObject(i);
            try {
                String type = credObj.getString("type");
                String id = credObj.optString("id", null);
                String description = credObj.optString("description", "");

                // 检查是否已存在
                StandardCredentials existing = findCredentialById(itemGroup, id);

                if (existing != null && !overwrite) {
                    skipped++;
                    continue;
                }

                StandardCredentials newCred = buildCredential(credObj, type, id, description);

                if (existing != null) {
                    // 覆盖更新
                    store.updateCredentials(Domain.global(), existing, newCred);
                    updated++;
                } else {
                    // 新增
                    store.addCredentials(Domain.global(), newCred);
                    imported++;
                }
            } catch (Exception e) {
                failed++;
                LOGGER.log(Level.WARNING, "Failed to import credential: " + credObj.optString("id", "unknown"), e);
            }
        }

        JSONObject result = new JSONObject();
        result.put("sourceFolder", sourceFolder);
        result.put("totalInBackup", credentialsArray.size());
        result.put("imported", imported);
        result.put("updated", updated);
        result.put("skipped", skipped);
        result.put("failed", failed);
        return result;
    }

    /**
     * 根据JSON构建凭据对象
     */
    private static StandardCredentials buildCredential(JSONObject credObj, String type, String id, String description) throws hudson.model.Descriptor.FormException {
        switch (type) {
            case "USERNAME_PASSWORD":
                return new UsernamePasswordCredentialsImpl(
                        CredentialsScope.GLOBAL,
                        id,
                        description,
                        credObj.getString("username"),
                        credObj.getString("password"));
            case "SECRET_TEXT":
                return new StringCredentialsImpl(
                        CredentialsScope.GLOBAL,
                        id,
                        description,
                        Secret.fromString(credObj.getString("secret")));
            case "SSH_KEY":
                BasicSSHUserPrivateKey.DirectEntryPrivateKeySource source =
                        new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(credObj.getString("privateKey"));
                return new BasicSSHUserPrivateKey(
                        CredentialsScope.GLOBAL,
                        id,
                        credObj.getString("username"),
                        source,
                        credObj.optString("passphrase", ""),
                        description);
            default:
                throw new IllegalArgumentException("Unsupported credential type: " + type);
        }
    }

    /**
     * 获取指定ItemGroup自身凭据存储中的所有凭据（不包含从父级继承的凭据）
     */
    private static List<StandardCredentials> getStoreCredentials(ItemGroup<?> itemGroup) {
        List<StandardCredentials> result = new java.util.ArrayList<>();
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
                        result.add((StandardCredentials) c);
                    }
                }
            }
        }
        return result;
    }

    /**
     * 根据ID查找凭据（仅在当前存储自身中查找，不包含从父级继承的凭据）
     */
    private static StandardCredentials findCredentialById(ItemGroup<?> itemGroup, String id) {
        if (id == null || id.isEmpty()) return null;
        for (StandardCredentials c : getStoreCredentials(itemGroup)) {
            if (c.getId().equals(id)) {
                return c;
            }
        }
        return null;
    }

    /**
     * AES-256-GCM加密（公开方法，供ZIP导出等场景使用）
     */
    public static String encryptData(String plaintext, String password) throws Exception {
        return encrypt(plaintext, password);
    }

    /**
     * AES-256-GCM解密（公开方法，供ZIP导入等场景使用）
     */
    public static String decryptData(String encryptedBase64, String password) throws Exception {
        return decrypt(encryptedBase64, password);
    }

    /**
     * AES-256-GCM加密
     */
    private static String encrypt(String plaintext, String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        // 从密码派生密钥 (PBKDF2)
        SecretKey key = deriveKey(password, salt);

        // 生成IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // 加密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // 组合: salt(16) + iv(12) + ciphertext
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

        // 提取salt, iv, ciphertext
        byte[] salt = new byte[16];
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(data, 0, salt, 0, 16);
        System.arraycopy(data, 16, iv, 0, GCM_IV_LENGTH);

        int ciphertextLength = data.length - 16 - GCM_IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(data, 16 + GCM_IV_LENGTH, ciphertext, 0, ciphertextLength);

        // 从密码派生密钥
        SecretKey key = deriveKey(password, salt);

        // 解密
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * PBKDF2从密码派生AES-256密钥
     */
    private static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                password.toCharArray(), salt, 65536, AES_KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
