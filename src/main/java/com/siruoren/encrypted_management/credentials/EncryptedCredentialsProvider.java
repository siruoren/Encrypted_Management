package com.siruoren.encrypted_management.credentials;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.CredentialsStoreAction;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.ModelObject;
import hudson.security.Permission;
import com.siruoren.encrypted_management.model.ModelEntry;
import com.siruoren.encrypted_management.service.EncryptedVariableService;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.jenkinsci.Symbol;

import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;

/**
 * CredentialsProvider that exposes encrypted variables as native Jenkins credentials.
 * This allows encrypted variables to be used in all Jenkins tasks just like native credentials.
 */
@Extension
@Symbol("encryptedManagement")
public class EncryptedCredentialsProvider extends CredentialsProvider {

    private static final Logger LOGGER = Logger.getLogger(EncryptedCredentialsProvider.class.getName());

    @NonNull
    @Override
    public Set<CredentialsScope> getScopes(@Nullable ModelObject object) {
        return Collections.singleton(CredentialsScope.GLOBAL);
    }

    @Nullable
    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type,
                                                           @Nullable ItemGroup itemGroup,
                                                           @Nullable Authentication authentication) {
        return getCredentials(type, itemGroup, authentication, Collections.emptyList());
    }

    @NonNull
    @Override
    public <C extends Credentials> List<C> getCredentials(@NonNull Class<C> type,
                                                           @Nullable ItemGroup itemGroup,
                                                           @Nullable Authentication authentication,
                                                           @NonNull List<DomainRequirement> domainRequirements) {
        List<C> result = new ArrayList<>();

        List<ModelEntry> allEntries = collectEntriesForItemGroup(itemGroup);

        for (ModelEntry entry : allEntries) {
            Credentials cred = toCredentials(entry);
            if (cred != null && type.isInstance(cred)) {
                result.add(type.cast(cred));
            }
        }

        return result;
    }

    /**
     * Collect all entries visible from the given ItemGroup, including parent folders.
     */
    private List<ModelEntry> collectEntriesForItemGroup(@Nullable ItemGroup itemGroup) {
        List<ModelEntry> entries = new ArrayList<>();

        if (itemGroup instanceof Folder) {
            Folder folder = (Folder) itemGroup;
            if (folder.hasPermission(Item.CONFIGURE) || folder.hasPermission(Item.READ)) {
                entries.addAll(EncryptedVariableService.getInstance().getEntries(folder.getFullName()));
            }
            ItemGroup parent = folder.getParent();
            while (parent instanceof Folder) {
                Folder parentFolder = (Folder) parent;
                if (parentFolder.hasPermission(Item.CONFIGURE) || parentFolder.hasPermission(Item.READ)) {
                    entries.addAll(EncryptedVariableService.getInstance().getEntries(parentFolder.getFullName()));
                }
                parent = parentFolder.getParent();
            }
        } else if (itemGroup instanceof Jenkins) {
            Jenkins jenkins = (Jenkins) itemGroup;
            for (Item item : jenkins.getAllItems()) {
                if (item instanceof Folder) {
                    Folder folder = (Folder) item;
                    if (folder.hasPermission(Item.CONFIGURE) || folder.hasPermission(Item.READ)) {
                        entries.addAll(EncryptedVariableService.getInstance().getEntries(folder.getFullName()));
                    }
                }
            }
        }

        return entries;
    }

    /**
     * Convert a ModelEntry to the appropriate Jenkins Credentials type.
     */
    @Nullable
    private Credentials toCredentials(@NonNull ModelEntry entry) {
        switch (entry.getType()) {
            case SECRET_TEXT:
            case SECRET_FILE:
                return EncryptedSecretTextCredentials.fromEntry(entry);
            case USERNAME_PASSWORD:
                return EncryptedUsernamePasswordCredentials.fromEntry(entry);
            case SSH_KEY_PAIR:
                return EncryptedSSHCredentials.fromEntry(entry);
            default:
                return null;
        }
    }

    @Override
    public CredentialsStore getStore(@Nullable ModelObject object) {
        if (object instanceof Folder) {
            return new EncryptedCredentialsStore(this, (Folder) object);
        }
        return null;
    }

    /**
     * Custom CredentialsStore for managing encrypted variables through the credentials UI.
     */
    private static class EncryptedCredentialsStore extends CredentialsStore {

        private final EncryptedCredentialsProvider provider;
        private final Folder folder;

        EncryptedCredentialsStore(EncryptedCredentialsProvider provider, Folder folder) {
            super(EncryptedCredentialsProvider.class);
            this.provider = provider;
            this.folder = folder;
        }

        @NonNull
        @Override
        public ModelObject getContext() {
            return folder;
        }

        @Override
        public boolean hasPermission(@NonNull Authentication a, @NonNull Permission permission) {
            return folder.getACL().hasPermission(a, permission);
        }

        @NonNull
        @Override
        public List<Credentials> getCredentials(@NonNull Domain domain) {
            List<Credentials> result = new ArrayList<>();
            List<ModelEntry> entries = EncryptedVariableService.getInstance().getEntries(folder.getFullName());
            for (ModelEntry entry : entries) {
                Credentials cred = provider.toCredentials(entry);
                if (cred != null) {
                    result.add(cred);
                }
            }
            return result;
        }

        @Override
        public boolean addCredentials(@NonNull Domain domain, @NonNull Credentials credentials) throws IOException {
            return false;
        }

        @Override
        public boolean removeCredentials(@NonNull Domain domain, @NonNull Credentials credentials) throws IOException {
            return false;
        }

        @Override
        public boolean updateCredentials(@NonNull Domain domain, @NonNull Credentials current,
                                          @NonNull Credentials replacement) throws IOException {
            return false;
        }

        @Nullable
        @Override
        public CredentialsStoreAction getStoreAction() {
            return null;
        }
    }
}
