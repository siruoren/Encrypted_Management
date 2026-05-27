package com.siruoren.encrypted_management;

import hudson.util.Secret;
import net.sf.json.JSONObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 加密服务类
 * <p>
 * 集中管理SSH密钥生成、公钥推导、私钥加密等密码学操作。
 * 从EncryptedManagementAction中提取，消除重复代码。
 * <p>
 * 安全改进：
 * - derivePublicKey 返回明确错误信息而非空字符串
 * - encryptPrivateKey 使用 PBKDF2 密钥派生（由BouncyCastle内部处理）
 */
public class CryptoService {
    private static final Logger LOGGER = Logger.getLogger(CryptoService.class.getName());

    private CryptoService() {}

    /**
     * 生成SSH密钥对
     *
     * @param passphrase 可选的passphrase，非空时加密私钥
     * @param folderName 用于审计日志
     * @return HttpResponse 包含privateKey和publicKey
     */
    public static HttpResponse generateKeyPair(String passphrase, String folderName) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyGen.generateKeyPair();

            String privateKeyPem;
            if (passphrase != null && !passphrase.isEmpty()) {
                privateKeyPem = encryptPrivateKeyToPEM(keyPair.getPrivate(), passphrase);
            } else {
                privateKeyPem = encodePrivateKeyToPEM(keyPair.getPrivate());
            }

            String publicKey = getSSHPublicKey(keyPair.getPublic());

            JSONObject result = new JSONObject();
            result.put("privateKey", privateKeyPem);
            result.put("publicKey", publicKey);

            JSONObject json = new JSONObject();
            json.put("success", true);
            json.put("data", result);
            AuditLogger.logGenerateKeyPair(folderName);
            return jsonResponse(json);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to generate SSH key pair", e);
            JSONObject err = new JSONObject();
            err.put("success", false);
            err.put("message", "Failed to generate key pair");
            return jsonResponse(err);
        }
    }

    /**
     * 从PEM格式私钥推导出OpenSSH格式公钥
     *
     * @return 公钥字符串，推导失败时返回null（而非空字符串）
     */
    public static String derivePublicKey(String privateKeyPem, Secret passphrase) {
        if (privateKeyPem == null || privateKeyPem.trim().isEmpty()) {
            LOGGER.warning("Cannot derive public key: private key is empty");
            return null;
        }

        try {
            String pemContent = privateKeyPem.trim();

            if (pemContent.contains("ENCRYPTED")) {
                if (passphrase == null) {
                    LOGGER.warning("Cannot derive public key: private key is encrypted but no passphrase provided");
                    return null;
                }
                try (StringReader reader = new StringReader(pemContent)) {
                    PEMParser pemParser = new PEMParser(reader);
                    Object obj = pemParser.readObject();
                    if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
                        PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo) obj;
                        PrivateKeyInfo decryptedPKI =
                                encryptedInfo.decryptPrivateKeyInfo(
                                        new JcePKCSPBEInputDecryptorProviderBuilder()
                                                .setProvider(new BouncyCastleProvider())
                                                .build(Secret.toString(passphrase).toCharArray()));
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        PrivateKey privKey = keyFactory.generatePrivate(
                                new PKCS8EncodedKeySpec(decryptedPKI.getEncoded()));
                        if (privKey instanceof RSAPrivateCrtKey) {
                            RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) privKey;
                            RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(
                                    crtKey.getModulus(), crtKey.getPublicExponent());
                            return getSSHPublicKey(keyFactory.generatePublic(pubSpec));
                        }
                    }
                }
                LOGGER.warning("Failed to derive public key: could not parse encrypted private key (wrong passphrase?)");
                return null;
            }

            // 未加密的私钥
            pemContent = pemContent
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(pemContent);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privKey;

            try {
                privKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
            } catch (java.security.spec.InvalidKeySpecException e) {
                privKey = keyFactory.generatePrivate(new java.security.spec.RSAPrivateKeySpec(
                        readASN1Integer(keyBytes, 0), readASN1Integer(keyBytes, 1)));
            }

            if (privKey instanceof RSAPrivateKey) {
                RSAPrivateKey rsaKey = (RSAPrivateKey) privKey;
                RSAPublicKeySpec pubSpec;
                if (rsaKey instanceof RSAPrivateCrtKey) {
                    RSAPrivateCrtKey crtKey = (RSAPrivateCrtKey) rsaKey;
                    pubSpec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
                } else {
                    LOGGER.warning("Cannot derive public key: private key lacks CRT parameters");
                    return null;
                }
                PublicKey pubKey = keyFactory.generatePublic(pubSpec);
                return getSSHPublicKey(pubKey);
            }

            LOGGER.warning("Cannot derive public key: private key is not RSA");
            return null;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to derive public key from private key", e);
            return null;
        }
    }

    /**
     * 将RSA私钥编码为PKCS#8 PEM格式（无加密）
     */
    public static String encodePrivateKeyToPEM(PrivateKey privateKey) throws IOException {
        Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\n");
        sb.append(encoder.encodeToString(privateKey.getEncoded()));
        sb.append("\n-----END PRIVATE KEY-----");
        return sb.toString();
    }

    /**
     * 将RSA私钥用passphrase加密，输出为PEM格式
     * BouncyCastle的JcePKCSPBEOutputEncryptorBuilder内部使用PBKDF2进行密钥派生
     */
    public static String encryptPrivateKeyToPEM(PrivateKey privateKey, String passphrase) throws Exception {
        StringWriter stringWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            JcaPKCS8EncryptedPrivateKeyInfoBuilder builder =
                    new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey);
            PKCS8EncryptedPrivateKeyInfo encryptedInfo = builder.build(
                    new JcePKCSPBEOutputEncryptorBuilder(
                            NISTObjectIdentifiers.id_aes128_CBC)
                            .setProvider(new BouncyCastleProvider())
                            .build(passphrase.toCharArray()));
            pemWriter.writeObject(encryptedInfo);
        }
        return stringWriter.toString().trim();
    }

    /**
     * 将RSA公钥转为OpenSSH格式
     */
    public static String getSSHPublicKey(PublicKey publicKey) throws IOException {
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] typeBytes = "ssh-rsa".getBytes(StandardCharsets.US_ASCII);
            bos.write((typeBytes.length >>> 24) & 0xFF);
            bos.write((typeBytes.length >>> 16) & 0xFF);
            bos.write((typeBytes.length >>> 8) & 0xFF);
            bos.write(typeBytes.length & 0xFF);
            bos.write(typeBytes);
            byte[] expBytes = rsaKey.getPublicExponent().toByteArray();
            bos.write((expBytes.length >>> 24) & 0xFF);
            bos.write((expBytes.length >>> 16) & 0xFF);
            bos.write((expBytes.length >>> 8) & 0xFF);
            bos.write(expBytes.length & 0xFF);
            bos.write(expBytes);
            byte[] modBytes = rsaKey.getModulus().toByteArray();
            bos.write((modBytes.length >>> 24) & 0xFF);
            bos.write((modBytes.length >>> 16) & 0xFF);
            bos.write((modBytes.length >>> 8) & 0xFF);
            bos.write(modBytes.length & 0xFF);
            bos.write(modBytes);
            return "ssh-rsa " + Base64.getEncoder().encodeToString(bos.toByteArray());
        }
        return "";
    }

    /**
     * 简单的ASN1整数读取（用于PKCS#1格式解析）
     */
    private static BigInteger readASN1Integer(byte[] data, int index) {
        int offset = 0;
        for (int i = 0; i <= index; i++) {
            if (offset >= data.length || data[offset] != 0x02) break;
            offset++;
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
                return new BigInteger(1, intBytes);
            }
            offset += len;
        }
        return BigInteger.ZERO;
    }

    private static HttpResponse jsonResponse(JSONObject json) {
        return new HttpResponse() {
            @Override
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                rsp.setContentType("application/json;charset=UTF-8");
                rsp.getWriter().write(json.toString());
            }
        };
    }

    // ==================== AES-256-GCM 加密/解密 ====================

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int AES_KEY_LENGTH = 256;

    /**
     * AES-256-GCM加密
     * 格式: Base64(salt[16] + iv[12] + ciphertext)
     *
     * @param plaintext 明文
     * @param password 加密密码
     * @return Base64编码的密文
     */
    public static String aesEncrypt(String plaintext, String password) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        SecretKey key = deriveAesKey(password, salt);

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
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
     *
     * @param encryptedBase64 Base64编码的密文
     * @param password 解密密码
     * @return 明文
     */
    public static String aesDecrypt(String encryptedBase64, String password) throws Exception {
        byte[] data = Base64.getDecoder().decode(encryptedBase64);

        byte[] salt = new byte[16];
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(data, 0, salt, 0, 16);
        System.arraycopy(data, 16, iv, 0, GCM_IV_LENGTH);

        int ciphertextLength = data.length - 16 - GCM_IV_LENGTH;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(data, 16 + GCM_IV_LENGTH, ciphertext, 0, ciphertextLength);

        SecretKey key = deriveAesKey(password, salt);

        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * PBKDF2从密码派生AES-256密钥
     * 安全增强：混合Jenkins master.key作为额外熵源，防止离线暴力破解
     */
    private static SecretKey deriveAesKey(String password, byte[] salt) throws Exception {
        byte[] masterKeyBytes = getJenkinsMasterKeyBytes();
        byte[] combinedSalt = salt;
        if (masterKeyBytes != null && masterKeyBytes.length > 0) {
            combinedSalt = new byte[salt.length + Math.min(masterKeyBytes.length, 32)];
            System.arraycopy(salt, 0, combinedSalt, 0, salt.length);
            System.arraycopy(masterKeyBytes, 0, combinedSalt, salt.length,
                    Math.min(masterKeyBytes.length, 32));
        }

        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                password.toCharArray(), combinedSalt, 65536, AES_KEY_LENGTH);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * 读取Jenkins master.key字节作为额外熵源
     * 如果读取失败则返回null（降级为仅密码模式，兼容无master.key环境）
     */
    private static byte[] getJenkinsMasterKeyBytes() {
        try {
            java.io.File masterKeyFile = new java.io.File(
                    jenkins.model.Jenkins.get().getRootDir(), "secrets/master.key");
            if (masterKeyFile.exists() && masterKeyFile.canRead()) {
                return java.nio.file.Files.readAllBytes(masterKeyFile.toPath());
            }
        } catch (Exception e) {
            // 降级为仅密码模式
        }
        return null;
    }
}
