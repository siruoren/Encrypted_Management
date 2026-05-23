package com.siruoren.encrypted_management.credentials;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import com.siruoren.encrypted_management.model.ModelEntry;

/**
 * Credential implementation for Username & Password type.
 * Compatible with Jenkins native StandardUsernamePasswordCredentials.
 */
public class EncryptedUsernamePasswordCredentials extends BaseStandardCredentials implements StandardUsernamePasswordCredentials {

    private static final long serialVersionUID = 1L;

    private final String username;
    private final Secret password;

    public EncryptedUsernamePasswordCredentials(CredentialsScope scope, String id, String description,
                                                 String username, Secret password) {
        super(scope, id, description);
        this.username = username;
        this.password = password;
    }

    @NonNull
    @Override
    public String getUsername() {
        return username;
    }

    @NonNull
    @Override
    public Secret getPassword() {
        return password;
    }

    /**
     * Create from a ModelEntry.
     */
    public static EncryptedUsernamePasswordCredentials fromEntry(ModelEntry entry) {
        return new EncryptedUsernamePasswordCredentials(
            CredentialsScope.GLOBAL,
            entry.getFolderFullName() + "/" + entry.getName(),
            entry.getDescription(),
            entry.getUsername() != null ? entry.getUsername() : "",
            entry.getSecretValue()
        );
    }
}
