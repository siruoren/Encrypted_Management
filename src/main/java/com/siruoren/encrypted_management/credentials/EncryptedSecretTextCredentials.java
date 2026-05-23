package com.siruoren.encrypted_management.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import com.siruoren.encrypted_management.model.ModelEntry;

/**
 * Credential implementation for Secret Text type.
 * Compatible with Jenkins native credentials API.
 */
public class EncryptedSecretTextCredentials extends BaseStandardCredentials {

    private static final long serialVersionUID = 1L;

    private final Secret secret;

    public EncryptedSecretTextCredentials(CredentialsScope scope, String id, String description, Secret secret) {
        super(scope, id, description);
        this.secret = secret;
    }

    public Secret getSecret() {
        return secret;
    }

    /**
     * Create from a ModelEntry.
     */
    public static EncryptedSecretTextCredentials fromEntry(ModelEntry entry) {
        return new EncryptedSecretTextCredentials(
            CredentialsScope.GLOBAL,
            entry.getFolderFullName() + "/" + entry.getName(),
            entry.getDescription(),
            entry.getSecretValue()
        );
    }
}
