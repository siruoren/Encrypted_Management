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
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 凭据管理页面 Action
 * 自动读取当前文件夹的所有原生凭据，支持创建/更新/删除
 * 凭据类型完全兼容Jenkins原生凭据系统
 */
public class EncryptedManagementAction implements Action {
    private static final Logger LOGGER = Logger.getLogger(EncryptedManagementAction.class.getName());

    // 有限线程池，用于异步执行耗时操作（同步外部存储等），防阻塞防内存泄露
    private static final ExecutorService asyncExecutor = Executors.newFixedThreadPool(
            Runtime.getRuntime().availableProcessors(),
            new ThreadFactory() {
                private final AtomicInteger counter = new AtomicInteger(0);
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "EncryptedManagement-Async-" + counter.incrementAndGet());
                    t.setDaemon(true); // 守护线程，JVM关闭时自动退出
                    return t;
                }
            });

    private final Folder folder;

    public EncryptedManagementAction(@Nonnull Folder folder) {
        this.folder = folder;
    }

    @Override
    public String getIconFileName() {
        return folder.hasPermission(Item.CONFIGURE) ? "symbol-credentials plugin-encrypted-management" : null;
    }

    @Override
    public String getDisplayName() {
        return folder.hasPermission(Item.CONFIGURE) ? Messages.EncryptedManagementAction_DisplayName() : null;
    }

    @Override
    public String getUrlName() {
        return folder.hasPermission(Item.CONFIGURE) ? "Encrypted_Management" : null;
    }

    /**
     * 检查当前用户是否有权限操作此文件夹的凭据
     */
    public boolean hasPermission() {
        return folder.hasPermission(Item.CONFIGURE);
    }

    public Folder getFolder() {
        return folder;
    }

    public String getFolderFullName() {
        return folder.getFullName();
    }

    /**
     * 获取当前文件夹的凭据存储
     */
    private CredentialsStore getFolderStore() {
        for (CredentialsStore store : CredentialsProvider.lookupStores(folder)) {
            if (store.getContext() == folder) {
                return store;
            }
        }
        return null;
    }

    /**
     * 根据ID查找凭据
     */
    private StandardCredentials findCredentialById(String id) {
        List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) folder, null, Collections.emptyList());
        for (StandardCredentials c : creds) {
            if (c.getId().equals(id)) {
                return c;
            }
        }
        return null;
    }

    /**
     * API: 以JSON格式返回当前文件夹的所有凭据（页面自动加载）
     */
    public HttpResponse doListCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        JSONArray arr = new JSONArray();
        List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) folder, null, Collections.emptyList());

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
        result.put("folder", folder.getFullName());
        result.put("count", creds.size());

        return jsonResult(result);
    }

    /**
     * API: 解密指定凭据的值
     */
    @RequirePOST
    public HttpResponse doDecryptCredential(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

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
            // 从私钥推导公钥
            String publicKey = derivePublicKeyFromPrivate(ssh.getPrivateKey(), ssh.getPassphrase());
            if (publicKey != null && !publicKey.isEmpty()) {
                result.put("publicKey", publicKey);
            }
        }

        AuditLogger.logRead(folder.getFullName(), id, getCredentialsTypeKey(c));
        return jsonResult(result);
    }

    /**
     * API: 创建Secret Text凭据
     */
    @RequirePOST
    public HttpResponse doCreateSecretText(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String secret = req.getParameter("secret");

        if (secret == null || secret.trim().isEmpty()) {
            return errorResponse("Secret value is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
        }

        try {
            StringCredentialsImpl credential = new StringCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    Secret.fromString(secret));

            store.addCredentials(Domain.global(), credential);
            AuditLogger.logCreate(folder.getFullName(), credential.getId(), "SECRET_TEXT");
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
        folder.checkPermission(Item.CONFIGURE);

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

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
        }

        try {
            UsernamePasswordCredentialsImpl credential = new UsernamePasswordCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    username,
                    password);

            store.addCredentials(Domain.global(), credential);
            AuditLogger.logCreate(folder.getFullName(), credential.getId(), "USERNAME_PASSWORD");
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
        folder.checkPermission(Item.CONFIGURE);

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

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
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
            AuditLogger.logCreate(folder.getFullName(), credential.getId(), "SSH_KEY");
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
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String secret = req.getParameter("secret");

        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
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
            AuditLogger.logUpdate(folder.getFullName(), id, "SECRET_TEXT");
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
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
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
            AuditLogger.logUpdate(folder.getFullName(), id, "USERNAME_PASSWORD");
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
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String passphrase = req.getParameter("passphrase");
        String privateKey = req.getParameter("privateKey");

        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
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
            AuditLogger.logUpdate(folder.getFullName(), id, "SSH_KEY");
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
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
        }

        try {
            StandardCredentials c = findCredentialById(id);
            if (c == null) {
                return errorResponse("Credential not found: " + id);
            }

            boolean removed = store.removeCredentials(Domain.global(), c);
            if (removed) {
                AuditLogger.logDelete(folder.getFullName(), id, getCredentialsTypeKey(c));
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
     * 如果提供passphrase，则用passphrase加密私钥
     */
    @RequirePOST
    public HttpResponse doGenerateKeyPair(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String passphrase = req.getParameter("passphrase");

        try {
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new java.security.SecureRandom());
            java.security.KeyPair keyPair = keyGen.generateKeyPair();

            // 私钥 - PEM格式（如果有passphrase则加密）
            String privateKeyPem;
            if (passphrase != null && !passphrase.isEmpty()) {
                privateKeyPem = encryptPrivateKeyToPEM(keyPair.getPrivate(), passphrase);
            } else {
                privateKeyPem = encodePrivateKeyToPEM(keyPair.getPrivate());
            }

            // 公钥 - OpenSSH格式
            String publicKey = getSSHPublicKey(keyPair.getPublic());

            JSONObject result = new JSONObject();
            result.put("privateKey", privateKeyPem);
            result.put("publicKey", publicKey);

            JSONObject json = new JSONObject();
            json.put("success", true);
            json.put("data", result);
            AuditLogger.logGenerateKeyPair(folder.getFullName());
            return jsonResult(json);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to generate SSH key pair", e);
            return errorResponse("Failed to generate key pair: " + e.getMessage());
        }
    }

    /**
     * 将RSA私钥编码为PKCS#8 PEM格式（无加密）
     */
    private String encodePrivateKeyToPEM(java.security.PrivateKey privateKey) throws java.io.IOException {
        java.util.Base64.Encoder encoder = java.util.Base64.getMimeEncoder(64, "\n".getBytes());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        sb.append(encoder.encodeToString(privateKey.getEncoded()));
        sb.append("\n-----END PRIVATE KEY-----");
        return sb.toString();
    }

    /**
     * 将RSA私钥用passphrase加密，输出为PEM格式（PKCS#8 AES-128-CBC加密）
     */
    private String encryptPrivateKeyToPEM(java.security.PrivateKey privateKey, String passphrase) throws Exception {
        java.io.StringWriter stringWriter = new java.io.StringWriter();
        try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pemWriter = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(stringWriter)) {
            org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder builder =
                    new org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey);
            org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo encryptedInfo = builder.build(
                    new org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder(
                            org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes128_CBC)
                            .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
                            .build(passphrase.toCharArray()));
            pemWriter.writeObject(encryptedInfo);
        }
        return stringWriter.toString().trim();
    }

    /**
     * 将RSA公钥转为OpenSSH格式
     */
    private String getSSHPublicKey(java.security.PublicKey publicKey) throws java.io.IOException {
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) publicKey;
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            // key type
            byte[] typeBytes = "ssh-rsa".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            bos.write((typeBytes.length >>> 24) & 0xFF);
            bos.write((typeBytes.length >>> 16) & 0xFF);
            bos.write((typeBytes.length >>> 8) & 0xFF);
            bos.write(typeBytes.length & 0xFF);
            bos.write(typeBytes);
            // exponent
            byte[] expBytes = rsaKey.getPublicExponent().toByteArray();
            bos.write((expBytes.length >>> 24) & 0xFF);
            bos.write((expBytes.length >>> 16) & 0xFF);
            bos.write((expBytes.length >>> 8) & 0xFF);
            bos.write(expBytes.length & 0xFF);
            bos.write(expBytes);
            // modulus
            byte[] modBytes = rsaKey.getModulus().toByteArray();
            bos.write((modBytes.length >>> 24) & 0xFF);
            bos.write((modBytes.length >>> 16) & 0xFF);
            bos.write((modBytes.length >>> 8) & 0xFF);
            bos.write(modBytes.length & 0xFF);
            bos.write(modBytes);
            return "ssh-rsa " + java.util.Base64.getEncoder().encodeToString(bos.toByteArray());
        }
        return "";
    }

    /**
     * 从PEM格式私钥推导出OpenSSH格式公钥
     * 支持PKCS#8和PKCS#1格式，支持passphrase加密的私钥
     */
    private String derivePublicKeyFromPrivate(String privateKeyPem, Secret passphrase) {
        try {
            // 去除PEM头尾
            String pemContent = privateKeyPem.trim();
            byte[] keyBytes;

            if (pemContent.contains("ENCRYPTED")) {
                // 加密的私钥，需要用passphrase解密
                if (passphrase == null) {
                    return "";
                }
                try (java.io.StringReader reader = new java.io.StringReader(pemContent)) {
                    org.bouncycastle.openssl.PEMParser pemParser = new org.bouncycastle.openssl.PEMParser(reader);
                    Object obj = pemParser.readObject();
                    if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
                        org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo encryptedInfo =
                                (org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) obj;
                        org.bouncycastle.asn1.pkcs.PrivateKeyInfo decryptedPKI =
                                encryptedInfo.decryptPrivateKeyInfo(
                                        new org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder()
                                                .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider())
                                                .build(Secret.toString(passphrase).toCharArray()));
                        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
                        java.security.PrivateKey privKey = keyFactory.generatePrivate(
                                new java.security.spec.PKCS8EncodedKeySpec(decryptedPKI.getEncoded()));
                        if (privKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
                            java.security.interfaces.RSAPrivateCrtKey crtKey = (java.security.interfaces.RSAPrivateCrtKey) privKey;
                            java.security.spec.RSAPublicKeySpec pubSpec = new java.security.spec.RSAPublicKeySpec(
                                    crtKey.getModulus(), crtKey.getPublicExponent());
                            return getSSHPublicKey(keyFactory.generatePublic(pubSpec));
                        }
                    }
                }
                return "";
            }

            // 未加密的私钥
            pemContent = pemContent.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            keyBytes = java.util.Base64.getDecoder().decode(pemContent);

            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.PrivateKey privKey;

            try {
                privKey = keyFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(keyBytes));
            } catch (java.security.spec.InvalidKeySpecException e) {
                // 尝试PKCS#1格式
                privKey = keyFactory.generatePrivate(new java.security.spec.RSAPrivateKeySpec(
                        readASN1Integer(keyBytes, 0), readASN1Integer(keyBytes, 1)));
            }

            if (privKey instanceof java.security.interfaces.RSAPrivateKey) {
                java.security.interfaces.RSAPrivateKey rsaKey = (java.security.interfaces.RSAPrivateKey) privKey;
                java.security.spec.RSAPublicKeySpec pubSpec;
                if (rsaKey instanceof java.security.interfaces.RSAPrivateCrtKey) {
                    java.security.interfaces.RSAPrivateCrtKey crtKey = (java.security.interfaces.RSAPrivateCrtKey) rsaKey;
                    pubSpec = new java.security.spec.RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
                } else {
                    // 没有CRT信息，无法推导公钥
                    return "";
                }
                java.security.PublicKey pubKey = keyFactory.generatePublic(pubSpec);
                return getSSHPublicKey(pubKey);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to derive public key from private key", e);
        }
        return "";
    }

    /**
     * 简单的ASN1整数读取（用于PKCS#1格式解析）
     */
    private java.math.BigInteger readASN1Integer(byte[] data, int index) {
        int offset = 0;
        for (int i = 0; i <= index; i++) {
            if (offset >= data.length || data[offset] != 0x02) break;
            offset++; // skip tag
            int len = data[offset++] & 0xFF;
            if (len > 127) {
                int lenBytes = len & 0x7F;
                len = 0;
                for (int j = 0; j < lenBytes; j++) {
                    len = (len << 8) | (data[offset++] & 0xFF);
                }
            }
            if (i == index) {
                byte[] intBytes = new byte[len];
                System.arraycopy(data, offset, intBytes, 0, len);
                return new java.math.BigInteger(1, intBytes);
            }
            offset += len;
        }
        return java.math.BigInteger.ZERO;
    }

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

    // ==================== 审计日志 API ====================

    /**
     * API: 查询审计日志
     */
    @RequirePOST
    public HttpResponse doAuditLog(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

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

    /**
     * API: 配置审计日志保留天数
     */
    @RequirePOST
    public HttpResponse doConfigureAuditLog(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String daysParam = req.getParameter("maxRetentionDays");
        if (daysParam != null && !daysParam.isEmpty()) {
            try {
                int days = Integer.parseInt(daysParam);
                if (days < 1) {
                    return errorResponse("Retention days must be at least 1");
                }
                AuditLogger.setMaxLogFiles(days);
                AuditLogger.log(folder.getFullName(), "CONFIGURE_AUDIT", "*", "*", "maxRetentionDays=" + days);
                return successResponse("Audit log retention set to " + days + " days");
            } catch (NumberFormatException e) {
                return errorResponse("Invalid retention days value");
            }
        }
        return errorResponse("Missing maxRetentionDays parameter");
    }

    // ==================== 备份/导出/导入 API ====================

    /**
     * API: 导出凭据为加密数据（JSON返回，用于页面内粘贴复制）
     */
    @RequirePOST
    public HttpResponse doExportCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String password = req.getParameter("password");
        if (password == null || password.isEmpty()) {
            return errorResponse("Encryption password is required");
        }
        if (password.length() < 8) {
            return errorResponse("Password must be at least 8 characters");
        }

        try {
            String encryptedData = CredentialBackupService.exportCredentials(folder, password);
            AuditLogger.logExport(folder.getFullName(), "exported " + folder.getFullName());

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("data", encryptedData);
            result.put("folder", folder.getFullName());
            result.put("message", "Credentials exported successfully. Keep the encrypted data and password safe.");
            return jsonResult(result);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to export credentials", e);
            return errorResponse("Failed to export credentials: " + e.getMessage());
        }
    }

    /**
     * API: 导出凭据为加密文件下载
     */
    @RequirePOST
    public HttpResponse doExportCredentialsFile(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String password = req.getParameter("password");
        if (password == null || password.isEmpty()) {
            return errorResponse("Encryption password is required");
        }
        if (password.length() < 8) {
            return errorResponse("Password must be at least 8 characters");
        }

        try {
            String encryptedData = CredentialBackupService.exportCredentials(folder, password);
            AuditLogger.logExport(folder.getFullName(), "exported as file: " + folder.getFullName());

            String filename = "credentials-backup-" + folder.getFullName().replaceAll("[/\\\\]", "-")
                    + "-" + java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"))
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
            LOGGER.log(Level.SEVERE, "Failed to export credentials as file", e);
            return errorResponse("Failed to export credentials: " + e.getMessage());
        }
    }

    /**
     * API: 从加密数据导入凭据
     */
    @RequirePOST
    public HttpResponse doImportCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

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
            JSONObject importResult = CredentialBackupService.importCredentials(folder, encryptedData, password, overwrite);
            AuditLogger.logImport(folder.getFullName(), "imported: " + importResult.toString());

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult);
            result.put("message", "Credentials imported successfully");
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import credentials", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    /**
     * API: 从上传文件导入凭据
     * 前端使用FileReader读取文件内容后，通过importCredentials API导入
     * 此API保留作为multipart上传的备选入口
     */
    @RequirePOST
    public HttpResponse doImportCredentialsFile(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

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
            JSONObject importResult = CredentialBackupService.importCredentials(folder, encryptedData.trim(), password, overwrite);
            AuditLogger.logImport(folder.getFullName(), "imported from file: " + importResult.toString());

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("importResult", importResult);
            result.put("message", "Credentials imported successfully from file");
            return jsonResult(result);
        } catch (javax.crypto.AEADBadTagException e) {
            return errorResponse("Decryption failed: wrong password or corrupted data");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to import credentials from file", e);
            return errorResponse("Failed to import credentials: " + e.getMessage());
        }
    }

    // ==================== 外部存储 API ====================

    /**
     * API: 获取外部存储状态
     */
    @RequirePOST
    public HttpResponse doStorageStatus(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        JSONObject status = manager.getStatus();
        status.put("success", true);
        return jsonResult(status);
    }

    /**
     * API: 配置外部存储
     */
    @RequirePOST
    public HttpResponse doConfigureStorage(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

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
        AuditLogger.log(folder.getFullName(), "CONFIGURE_STORAGE", "*", "*", detail);
        return successResponse("External storage configuration saved");
    }

    /**
     * API: 测试外部存储连接
     */
    @RequirePOST
    public HttpResponse doTestStorageConnection(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        boolean connected = manager.testConnection();

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("connected", connected);
        return jsonResult(result);
    }

    /**
     * API: 同步凭据到外部存储（异步非阻塞）
     */
    @RequirePOST
    public HttpResponse doSyncToExternal(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        ExternalStorageManager manager = ExternalStorageManager.getInstance();
        if (!manager.isEnabled()) {
            return errorResponse("External storage is not enabled");
        }

        // 快照读取凭据列表，避免长时间持有引用
        final List<StandardCredentials> creds = new ArrayList<>(CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) folder, null, Collections.emptyList()));
        final String folderName = folder.getFullName();

        // 异步执行同步操作，不阻塞请求线程
        asyncExecutor.submit(new Runnable() {
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
                    LOGGER.info("Async sync completed: " + synced + " credentials synced for folder " + folderName);
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to sync credentials to external storage", e);
                }
            }
        });

        // 立即返回，不等待同步完成
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "Sync started in background for " + creds.size() + " credentials");
        return jsonResult(result);
    }

    /**
     * 通过 TransientActionFactory 自动为所有 Folder 添加此 Action
     */
    @Extension
    public static class ActionFactory extends TransientActionFactory<Folder> {
        @Override
        public Class<Folder> type() {
            return Folder.class;
        }

        @Override
        @Nonnull
        public Collection<? extends Action> createFor(@Nonnull Folder folder) {
            return Collections.singletonList(new EncryptedManagementAction(folder));
        }
    }
}
