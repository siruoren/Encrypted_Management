package com.siruoren.encrypted_management.action;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Item;
import com.siruoren.encrypted_management.model.ModelEntry;
import com.siruoren.encrypted_management.service.AsyncTaskService;
import com.siruoren.encrypted_management.service.EncryptedVariableService;
import com.siruoren.encrypted_management.service.SshKeyGenerator;
import com.siruoren.encrypted_management.validator.VariableNameValidator;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.WebMethod;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.kohsuke.stapler.json.JsonHttpResponse;

import edu.umd.cs.findbugs.annotations.NonNull;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Action attached to Folder items.
 * Only visible to users with CONFIGURE permission on the folder.
 */
public class FolderEncryptedAction implements Action {

    private static final Logger LOGGER = Logger.getLogger(FolderEncryptedAction.class.getName());

    private final Folder folder;

    public FolderEncryptedAction(Folder folder) {
        this.folder = folder;
    }

    @Override
    public String getIconFileName() {
        return folder.hasPermission(Item.CONFIGURE) ? "symbol-encrypted-folder" : null;
    }

    @Override
    public String getDisplayName() {
        return Messages.FolderAction_displayName();
    }

    @Override
    public String getUrlName() {
        return "encrypted-variables";
    }

    public Folder getFolder() {
        return folder;
    }

    public String getFolderFullName() {
        return folder.getFullName();
    }

    public boolean hasConfigurePermission() {
        return folder.hasPermission(Item.CONFIGURE);
    }

    /**
     * Get all encrypted entries for this folder.
     */
    public List<ModelEntry> getEntries() {
        return EncryptedVariableService.getInstance().getEntries(folder.getFullName());
    }

    /**
     * Get native Jenkins credentials for this folder (excluding our own encrypted credentials).
     */
    public List<NativeCredentialInfo> getNativeCredentials() {
        List<NativeCredentialInfo> result = new ArrayList<>();
        try {
            List<Credentials> creds = CredentialsProvider.lookupCredentials(
                Credentials.class, (hudson.model.Item) folder, null, Collections.emptyList()
            );
            for (Credentials cred : creds) {
                // Skip credentials from our own provider
                if (cred.getClass().getName().startsWith("com.siruoren.encrypted_management.credentials")) {
                    continue;
                }
                String id = "";
                String displayName = cred.getClass().getSimpleName();
                String description = "";
                String type = "CREDENTIAL";

                if (cred instanceof StandardCredentials) {
                    StandardCredentials sc = (StandardCredentials) cred;
                    id = sc.getId();
                    description = sc.getDescription() != null ? sc.getDescription() : "";
                }
                if (cred instanceof UsernamePasswordCredentials) {
                    type = "USERNAME_PASSWORD";
                    UsernamePasswordCredentials upc = (UsernamePasswordCredentials) cred;
                    displayName = upc.getUsername();
                } else if (cred instanceof com.cloudbees.plugins.credentials.common.StandardUsernameCredentials) {
                    type = "SSH_KEY_PAIR";
                    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials suc =
                        (com.cloudbees.plugins.credentials.common.StandardUsernameCredentials) cred;
                    displayName = suc.getUsername();
                }
                result.add(new NativeCredentialInfo(id, displayName, type, description));
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to lookup native credentials for folder: " + folder.getFullName(), e);
        }
        return result;
    }

    /**
     * Simple POJO for native credential info display.
     */
    public static class NativeCredentialInfo {
        private final String id;
        private final String displayName;
        private final String type;
        private final String description;

        public NativeCredentialInfo(String id, String displayName, String type, String description) {
            this.id = id;
            this.displayName = displayName;
            this.type = type;
            this.description = description;
        }

        public String getId() { return id; }
        public String getDisplayName() { return displayName; }
        public String getType() { return type; }
        public String getDescription() { return description; }
    }

    /**
     * Create a new encrypted variable.
     */
    @RequirePOST
    public HttpResponse doCreateEntry(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");
        String typeStr = form.optString("type", "SECRET_TEXT");
        String value = form.optString("secretValue", "");
        String description = form.optString("description", "");

        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        if (EncryptedVariableService.getInstance().entryExists(folder.getFullName(), name)) {
            return errorResponse(Messages.EncryptedManagementLink_entryAlreadyExists(name));
        }

        ModelEntry.EntryType type;
        try {
            type = ModelEntry.EntryType.valueOf(typeStr);
        } catch (IllegalArgumentException e) {
            return errorResponse(Messages.EncryptedManagementLink_invalidType());
        }

        ModelEntry entry = new ModelEntry();
        entry.setName(name.trim());
        entry.setType(type);
        entry.setDescription(description);
        entry.setFolderFullName(folder.getFullName());

        switch (type) {
            case SECRET_TEXT:
                entry.setSecretValue(hudson.util.Secret.fromString(value));
                break;
            case USERNAME_PASSWORD:
                String username = form.optString("username", "");
                entry.setUsername(username);
                entry.setSecretValue(hudson.util.Secret.fromString(value));
                break;
            case SSH_KEY_PAIR:
                return errorResponse(Messages.EncryptedManagementLink_useSshKeyGenerator());
            case SECRET_FILE:
                entry.setSecretValue(hudson.util.Secret.fromString(value));
                break;
            default:
                entry.setSecretValue(hudson.util.Secret.fromString(value));
        }

        Future<Boolean> future = AsyncTaskService.getInstance().submit(() -> {
            EncryptedVariableService.getInstance().saveEntry(entry);
            return true;
        });

        try {
            future.get();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to save encrypted variable", e);
            return errorResponse(Messages.EncryptedManagementLink_saveFailed(e.getMessage()));
        }

        return successResponse(Messages.EncryptedManagementLink_entryCreated(name));
    }

    /**
     * Generate SSH key pair - preview only, does not save.
     * Returns the generated key pair info for user to confirm.
     */
    @RequirePOST
    public HttpResponse doGenerateSshKeyPreview(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");
        int keySize = form.optInt("keySize", 4096);
        String comment = form.optString("comment", "");
        String description = form.optString("description", "");
        String passphrase = form.optString("passphrase", "");

        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        if (EncryptedVariableService.getInstance().entryExists(folder.getFullName(), name)) {
            return errorResponse(Messages.EncryptedManagementLink_entryAlreadyExists(name));
        }

        if (keySize != 2048 && keySize != 3072 && keySize != 4096 && keySize != 8192) {
            return errorResponse(Messages.EncryptedManagementLink_invalidKeySize());
        }

        try {
            ModelEntry entry = SshKeyGenerator.generateKeyPairJsch(name, keySize, comment, description, folder.getFullName(), passphrase);

            JSONObject result = new JSONObject();
            result.put("status", "ok");
            result.put("name", entry.getName());
            result.put("type", entry.getType().name());
            result.put("privateKey", entry.getDecryptedValue());
            result.put("publicKey", entry.getSshPublicKey());
            result.put("passphrase", entry.getDecryptedPassphrase() != null ? entry.getDecryptedPassphrase() : "");
            result.put("description", entry.getDescription() != null ? entry.getDescription() : "");
            result.put("keySize", keySize);
            result.put("comment", comment != null ? comment : "");

            return jsonResult(result);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to generate SSH key pair preview", e);
            return errorResponse(Messages.EncryptedManagementLink_sshKeyGenFailed(e.getMessage()));
        }
    }

    /**
     * Save SSH key pair after user confirms the preview.
     */
    @RequirePOST
    public HttpResponse doSaveSshKey(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");
        String privateKey = form.optString("privateKey", "");
        String publicKey = form.optString("publicKey", "");
        String passphrase = form.optString("passphrase", "");
        String description = form.optString("description", "");
        int keySize = form.optInt("keySize", 4096);
        String comment = form.optString("comment", "");

        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        if (EncryptedVariableService.getInstance().entryExists(folder.getFullName(), name)) {
            return errorResponse(Messages.EncryptedManagementLink_entryAlreadyExists(name));
        }

        ModelEntry entry = new ModelEntry();
        entry.setName(name.trim());
        entry.setType(ModelEntry.EntryType.SSH_KEY_PAIR);
        entry.setSecretValue(hudson.util.Secret.fromString(privateKey));
        entry.setSshPublicKey(publicKey);
        if (passphrase != null && !passphrase.isEmpty()) {
            entry.setPassphrase(hudson.util.Secret.fromString(passphrase));
        }
        // Put public key info in description if description is empty
        if ((description == null || description.isEmpty()) && publicKey != null) {
            entry.setDescription("SSH Public Key: " + publicKey);
        } else {
            entry.setDescription(description);
        }
        entry.setFolderFullName(folder.getFullName());

        Future<Boolean> future = AsyncTaskService.getInstance().submit(() -> {
            EncryptedVariableService.getInstance().saveEntry(entry);
            return true;
        });

        try {
            future.get();
            return successResponse(Messages.EncryptedManagementLink_sshKeyGenerated(name));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to save SSH key pair", e);
            return errorResponse(Messages.EncryptedManagementLink_sshKeyGenFailed(e.getMessage()));
        }
    }

    /**
     * Generate SSH key pair.
     */
    @RequirePOST
    public HttpResponse doGenerateSshKey(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");
        int keySize = form.optInt("keySize", 4096);
        String comment = form.optString("comment", "");
        String description = form.optString("description", "");

        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        if (EncryptedVariableService.getInstance().entryExists(folder.getFullName(), name)) {
            return errorResponse(Messages.EncryptedManagementLink_entryAlreadyExists(name));
        }

        if (keySize != 2048 && keySize != 3072 && keySize != 4096 && keySize != 8192) {
            return errorResponse(Messages.EncryptedManagementLink_invalidKeySize());
        }

        Future<ModelEntry> future = AsyncTaskService.getInstance().submit(() -> {
            ModelEntry entry = SshKeyGenerator.generateKeyPairJsch(name, keySize, comment, description, folder.getFullName());
            EncryptedVariableService.getInstance().saveEntry(entry);
            return entry;
        });

        try {
            future.get();
            return successResponse(Messages.EncryptedManagementLink_sshKeyGenerated(name));
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to generate SSH key pair", e);
            return errorResponse(Messages.EncryptedManagementLink_sshKeyGenFailed(e.getMessage()));
        }
    }

    /**
     * Update an existing encrypted variable.
     */
    @RequirePOST
    public HttpResponse doUpdateEntry(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");

        ModelEntry existing = EncryptedVariableService.getInstance().getEntry(folder.getFullName(), name);
        if (existing == null) {
            return errorResponse(Messages.EncryptedManagementLink_entryNotFound(name));
        }

        String value = form.optString("secretValue", "");
        String description = form.optString("description", "");

        if (!value.isEmpty()) {
            existing.setSecretValue(hudson.util.Secret.fromString(value));
        }
        existing.setDescription(description);

        if (existing.getType() == ModelEntry.EntryType.USERNAME_PASSWORD) {
            String username = form.optString("username", "");
            existing.setUsername(username);
        }

        Future<Boolean> future = AsyncTaskService.getInstance().submit(() -> {
            EncryptedVariableService.getInstance().saveEntry(existing);
            return true;
        });

        try {
            future.get();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to update encrypted variable", e);
            return errorResponse(Messages.EncryptedManagementLink_updateFailed(e.getMessage()));
        }

        return successResponse(Messages.EncryptedManagementLink_entryUpdated(name));
    }

    /**
     * Delete an encrypted variable.
     */
    @RequirePOST
    public HttpResponse doDeleteEntry(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");

        Future<Boolean> future = AsyncTaskService.getInstance().submit(() -> {
            return EncryptedVariableService.getInstance().deleteEntry(folder.getFullName(), name);
        });

        try {
            Boolean result = future.get();
            if (result) {
                return successResponse(Messages.EncryptedManagementLink_entryDeleted(name));
            } else {
                return errorResponse(Messages.EncryptedManagementLink_entryNotFound(name));
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to delete encrypted variable", e);
            return errorResponse(Messages.EncryptedManagementLink_deleteFailed(e.getMessage()));
        }
    }

    /**
     * Decrypt and show value (AJAX endpoint).
     */
    @RequirePOST
    public HttpResponse doDecryptValue(StaplerRequest req) throws IOException, ServletException {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject form = req.getSubmittedForm();
        String name = form.optString("name", "");

        ModelEntry entry = EncryptedVariableService.getInstance().getEntry(folder.getFullName(), name);
        if (entry == null) {
            return errorResponse(Messages.EncryptedManagementLink_entryNotFound(name));
        }

        JSONObject result = new JSONObject();
        result.put("status", "ok");
        result.put("name", entry.getName());
        result.put("type", entry.getType().name());
        result.put("decryptedValue", entry.getDecryptedValue());
        if (entry.getType() == ModelEntry.EntryType.SSH_KEY_PAIR) {
            result.put("sshPublicKey", entry.getSshPublicKey());
        }
        if (entry.getType() == ModelEntry.EntryType.USERNAME_PASSWORD) {
            result.put("username", entry.getUsername());
        }

        return jsonResult(result);
    }

    /**
     * Decrypt a specific entry by name (GET endpoint for sidebar).
     * Checks user permission before returning decrypted value.
     */
    @RequirePOST
    public HttpResponse doDecryptEntry(StaplerRequest req) throws IOException, ServletException {
        String name = req.getParameter("name");
        if (name == null || name.trim().isEmpty()) {
            return errorResponse(Messages.EncryptedManagementLink_entryNotFound(""));
        }

        // Check permission - user must have CONFIGURE permission to decrypt
        if (!folder.hasPermission(Item.CONFIGURE)) {
            return errorResponse(Messages.EncryptedManagementLink_noPermission());
        }

        ModelEntry entry = EncryptedVariableService.getInstance().getEntry(folder.getFullName(), name.trim());
        if (entry == null) {
            return errorResponse(Messages.EncryptedManagementLink_entryNotFound(name));
        }

        JSONObject result = new JSONObject();
        result.put("status", "ok");
        result.put("name", entry.getName());
        result.put("type", entry.getType().name());
        result.put("description", entry.getDescription() != null ? entry.getDescription() : "");
        result.put("decryptedValue", entry.getDecryptedValue());
        if (entry.getType() == ModelEntry.EntryType.SSH_KEY_PAIR && entry.getSshPublicKey() != null) {
            result.put("sshPublicKey", entry.getSshPublicKey());
        }
        if (entry.getType() == ModelEntry.EntryType.USERNAME_PASSWORD && entry.getUsername() != null) {
            result.put("username", entry.getUsername());
        }

        return jsonResult(result);
    }

    /**
     * API JSON endpoint for AJAX data loading.
     */
    @WebMethod(name = "api/json")
    public HttpResponse doApiJson() {
        folder.checkPermission(Item.CONFIGURE);

        JSONObject result = new JSONObject();
        JSONArray entriesArray = new JSONArray();
        for (ModelEntry entry : getEntries()) {
            JSONObject entryObj = new JSONObject();
            entryObj.put("name", entry.getName());
            entryObj.put("type", entry.getType().name());
            entryObj.put("description", entry.getDescription() != null ? entry.getDescription() : "");
            entryObj.put("createdTimestamp", entry.getCreatedTimestamp());
            entryObj.put("updatedTimestamp", entry.getUpdatedTimestamp());
            if (entry.getType() == ModelEntry.EntryType.USERNAME_PASSWORD && entry.getUsername() != null) {
                entryObj.put("username", entry.getUsername());
            }
            entriesArray.add(entryObj);
        }
        result.put("entries", entriesArray);
        return new JsonHttpResponse(result);
    }

    private HttpResponse errorResponse(String message) {
        return new HttpResponse() {
            @Override
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                rsp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                rsp.setContentType("application/json;charset=UTF-8");
                JSONObject result = new JSONObject();
                result.put("status", "error");
                result.put("message", message);
                rsp.getWriter().write(result.toString());
            }
        };
    }

    private HttpResponse successResponse(String message) {
        return new HttpResponse() {
            @Override
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                rsp.setContentType("application/json;charset=UTF-8");
                JSONObject result = new JSONObject();
                result.put("status", "ok");
                result.put("message", message);
                rsp.getWriter().write(result.toString());
            }
        };
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

    /**
     * Factory that attaches FolderEncryptedAction to Folder items.
     */
    @Extension
    public static class Factory extends TransientActionFactory<Folder> {

        @Override
        public Class<Folder> type() {
            return Folder.class;
        }

        @NonNull
        @Override
        public Collection<? extends Action> createFor(@NonNull Folder folder) {
            return Collections.singleton(new FolderEncryptedAction(folder));
        }
    }
}
