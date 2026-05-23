package com.siruoren.encrypted_management.credentials;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.util.Secret;
import com.siruoren.encrypted_management.model.ModelEntry;

import java.util.Collections;
import java.util.List;

/**
 * Credential implementation for SSH Key Pair type.
 * Compatible with Jenkins native SSHUserPrivateKey.
 */
public class EncryptedSSHCredentials extends BaseStandardCredentials implements SSHUserPrivateKey {

    private static final long serialVersionUID = 1L;

    private final Secret privateKey;
    private final Secret passphrase;
    private final String publicKeys;

    public EncryptedSSHCredentials(CredentialsScope scope, String id, String description,
                                    Secret privateKey, @Nullable Secret passphrase, @Nullable String publicKeys) {
        super(scope, id, description);
        this.privateKey = privateKey;
        this.passphrase = passphrase;
        this.publicKeys = publicKeys;
    }

    @NonNull
    @Override
    public String getUsername() {
        return getId();
    }

    @NonNull
    public String getDisplayName() {
        return getId();
    }

    @Nullable
    @Override
    public Secret getPassphrase() {
        return passphrase;
    }

    @NonNull
    @Override
    public String getPrivateKey() {
        return Secret.toString(privateKey);
    }

    @NonNull
    @Override
    public List<String> getPrivateKeys() {
        return Collections.singletonList(getPrivateKey());
    }

    /**
     * Get the SSH public key in OpenSSH format.
     */
    @Nullable
    public String getPublicKeys() {
        return publicKeys;
    }

    /**
     * Create from a ModelEntry.
     */
    public static EncryptedSSHCredentials fromEntry(ModelEntry entry) {
        return new EncryptedSSHCredentials(
            CredentialsScope.GLOBAL,
            entry.getFolderFullName() + "/" + entry.getName(),
            entry.getDescription(),
            entry.getSecretValue(),
            null,
            entry.getSshPublicKey()
        );
    }
}
