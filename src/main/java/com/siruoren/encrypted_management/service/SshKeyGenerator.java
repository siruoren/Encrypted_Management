package com.siruoren.encrypted_management.service;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.KeyPair;
import hudson.util.Secret;
import com.siruoren.encrypted_management.model.ModelEntry;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * Service for generating SSH key pairs.
 */
public class SshKeyGenerator {

    private static final int DEFAULT_KEY_SIZE = 4096;
    private static final String RSA_ALGORITHM = "RSA";

    /**
     * Generates an RSA SSH key pair and returns a ModelEntry of type SSH_KEY_PAIR.
     * The private key is stored as the secret value, and the public key is stored separately.
     *
     * @param variableName   the name for the encrypted variable
     * @param keySize        the key size (2048, 4096, etc.)
     * @param description    optional description
     * @param folderFullName the folder full name
     * @return a ModelEntry containing the SSH key pair
     */
    public static ModelEntry generateKeyPair(String variableName, int keySize, String description, String folderFullName) throws Exception {
        if (keySize <= 0) {
            keySize = DEFAULT_KEY_SIZE;
        }

        // Generate RSA key pair using Bouncy Castle
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(keySize);
        java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Convert private key to PEM format (PKCS8)
        String privateKeyPem = privateKeyToPem(privateKey);

        // Convert public key to OpenSSH format
        String publicKeyOpenssh = publicKeyToOpenSsh(publicKey);

        // Create the entry - private key as the secret value
        ModelEntry entry = new ModelEntry();
        entry.setName(variableName);
        entry.setType(ModelEntry.EntryType.SSH_KEY_PAIR);
        entry.setSecretValue(Secret.fromString(privateKeyPem));
        entry.setSshPublicKey(publicKeyOpenssh);
        entry.setDescription(description);
        entry.setFolderFullName(folderFullName);

        return entry;
    }

    private static String privateKeyToPem(PrivateKey privateKey) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JcaPEMWriter writer = new JcaPEMWriter(new OutputStreamWriter(baos, StandardCharsets.UTF_8))) {
            JcaPKCS8Generator generator = new JcaPKCS8Generator(privateKey, null);
            PemObject pemObject = generator.generate();
            writer.writeObject(pemObject);
        }
        return baos.toString(StandardCharsets.UTF_8);
    }

    private static String publicKeyToOpenSsh(PublicKey publicKey) throws Exception {
        // Format: ssh-rsa AAAA... base64encoded
        byte[] encoded = publicKey.getEncoded();
        String base64 = Base64.getEncoder().encodeToString(encoded);
        return "ssh-rsa " + base64;
    }

    /**
     * Quick generate using JSch for standard OpenSSH format.
     */
    public static ModelEntry generateKeyPairJsch(String variableName, int keySize, String comment, String description, String folderFullName) throws Exception {
        return generateKeyPairJsch(variableName, keySize, comment, description, folderFullName, null);
    }

    /**
     * Quick generate using JSch for standard OpenSSH format with optional passphrase.
     */
    public static ModelEntry generateKeyPairJsch(String variableName, int keySize, String comment, String description, String folderFullName, String passphrase) throws Exception {
        if (keySize <= 0) {
            keySize = DEFAULT_KEY_SIZE;
        }

        JSch jsch = new JSch();
        KeyPair keyPair = KeyPair.genKeyPair(jsch, KeyPair.RSA, keySize);

        // Get private key bytes (with passphrase if provided)
        ByteArrayOutputStream privateKeyOut = new ByteArrayOutputStream();
        if (passphrase != null && !passphrase.isEmpty()) {
            keyPair.writePrivateKey(privateKeyOut, passphrase.getBytes(StandardCharsets.UTF_8));
        } else {
            keyPair.writePrivateKey(privateKeyOut);
        }
        String privateKeyStr = privateKeyOut.toString(StandardCharsets.UTF_8);

        // Get public key bytes
        ByteArrayOutputStream publicKeyOut = new ByteArrayOutputStream();
        keyPair.writePublicKey(publicKeyOut, comment != null ? comment : variableName);
        String publicKeyStr = publicKeyOut.toString(StandardCharsets.UTF_8).trim();

        keyPair.dispose();

        ModelEntry entry = new ModelEntry();
        entry.setName(variableName);
        entry.setType(ModelEntry.EntryType.SSH_KEY_PAIR);
        entry.setSecretValue(Secret.fromString(privateKeyStr));
        entry.setSshPublicKey(publicKeyStr);
        entry.setDescription(description);
        entry.setFolderFullName(folderFullName);
        if (passphrase != null && !passphrase.isEmpty()) {
            entry.setPassphrase(Secret.fromString(passphrase));
        }

        return entry;
    }
}
