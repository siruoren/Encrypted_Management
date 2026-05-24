package com.siruoren.encrypted_management.action;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ManagementLink;
import com.siruoren.encrypted_management.model.ModelEntry;
import com.siruoren.encrypted_management.service.EncryptedVariableService;
import com.siruoren.encrypted_management.service.SshKeyGenerator;
import com.siruoren.encrypted_management.validator.VariableNameValidator;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import edu.umd.cs.findbugs.annotations.NonNull;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ManagementLink for the root-level entry point.
 * Only visible to administrators on the Jenkins homepage.
 */
@Extension
@Symbol("encryptedManagement")
public class EncryptedManagementLink extends ManagementLink {

    private static final Logger LOGGER = Logger.getLogger(EncryptedManagementLink.class.getName());

    @Override
    public String getIconFileName() {
        return Jenkins.get().hasPermission(Jenkins.ADMINISTER) ? "symbol-encrypted-folder" : null;
    }

    @Override
    public String getDisplayName() {
        return Messages.EncryptedManagementLink_displayName();
    }

    @Override
    public String getDescription() {
        return Messages.EncryptedManagementLink_description();
    }

    @Override
    public String getUrlName() {
        return "encrypted-management";
    }

    @Override
    public Category getCategory() {
        return Category.SECURITY;
    }

    /**
     * Check if the current user has admin permission.
     */
    public boolean hasAdminPermission() {
        return Jenkins.get().hasPermission(Jenkins.ADMINISTER);
    }

    /**
     * Get all folders that the current user can configure.
     */
    public List<Folder> getConfigurableFolders() {
        List<Folder> folders = new ArrayList<>();
        Jenkins jenkins = Jenkins.get();
        for (Item item : jenkins.getAllItems()) {
            if (item instanceof Folder) {
                if (item.hasPermission(Item.CONFIGURE)) {
                    folders.add((Folder) item);
                }
            }
        }
        return folders;
    }

    /**
     * Get entries for a specific folder.
     */
    public List<ModelEntry> getEntriesForFolder(String folderFullName) {
        return EncryptedVariableService.getInstance().getEntries(folderFullName);
    }

    /**
     * DoCreate a new encrypted variable.
     */
    @RequirePOST
    public HttpResponse doCreateEntry(StaplerRequest req) throws IOException, ServletException {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        String name = req.getParameter("name");
        String typeStr = req.getParameter("type");
        String value = req.getParameter("secretValue");
        String description = req.getParameter("description");
        String folderFullName = req.getParameter("folderFullName");
        if (name == null) name = "";
        if (typeStr == null) typeStr = "SECRET_TEXT";
        if (value == null) value = "";
        if (description == null) description = "";
        if (folderFullName == null) folderFullName = "";

        // Validate variable name
        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        // Check if entry already exists
        if (EncryptedVariableService.getInstance().entryExists(folderFullName, name)) {
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
        entry.setFolderFullName(folderFullName);

        switch (type) {
            case SECRET_TEXT:
                entry.setSecretValue(hudson.util.Secret.fromString(value));
                break;
            case USERNAME_PASSWORD:
                String username = req.getParameter("username");
                if (username == null) username = "";
                entry.setUsername(username);
                entry.setSecretValue(hudson.util.Secret.fromString(value));
                break;
            case SSH_KEY_PAIR:
                // SSH key pair should be generated via doGenerateSshKey
                return errorResponse(Messages.EncryptedManagementLink_useSshKeyGenerator());
            case SECRET_FILE:
                entry.setSecretValue(hudson.util.Secret.fromString(value));
                break;
            default:
                entry.setSecretValue(hudson.util.Secret.fromString(value));
        }

        try {
            EncryptedVariableService.getInstance().saveEntry(entry);
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
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        String name = req.getParameter("name");
        String keySizeStr = req.getParameter("keySize");
        String comment = req.getParameter("comment");
        String description = req.getParameter("description");
        String folderFullName = req.getParameter("folderFullName");
        String passphrase = req.getParameter("passphrase");
        if (name == null) name = "";
        if (comment == null) comment = "";
        if (description == null) description = "";
        if (folderFullName == null) folderFullName = "";
        if (passphrase == null) passphrase = "";
        int keySize = 4096;
        try { keySize = Integer.parseInt(keySizeStr); } catch (Exception e) {}

        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        if (EncryptedVariableService.getInstance().entryExists(folderFullName, name)) {
            return errorResponse(Messages.EncryptedManagementLink_entryAlreadyExists(name));
        }

        if (keySize != 2048 && keySize != 3072 && keySize != 4096 && keySize != 8192) {
            return errorResponse(Messages.EncryptedManagementLink_invalidKeySize());
        }

        try {
            ModelEntry entry = SshKeyGenerator.generateKeyPairJsch(name, keySize, comment, description, folderFullName, passphrase);

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
            result.put("folderFullName", folderFullName);

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
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        String name = req.getParameter("name");
        String privateKey = req.getParameter("privateKey");
        String publicKey = req.getParameter("publicKey");
        String passphrase = req.getParameter("passphrase");
        String description = req.getParameter("description");
        String folderFullName = req.getParameter("folderFullName");
        String keySizeStr = req.getParameter("keySize");
        String comment = req.getParameter("comment");
        if (name == null) name = "";
        if (privateKey == null) privateKey = "";
        if (publicKey == null) publicKey = "";
        if (passphrase == null) passphrase = "";
        if (description == null) description = "";
        if (folderFullName == null) folderFullName = "";
        if (comment == null) comment = "";
        int keySize = 4096;
        try { keySize = Integer.parseInt(keySizeStr); } catch (Exception e) {}

        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        if (EncryptedVariableService.getInstance().entryExists(folderFullName, name)) {
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
        if ((description == null || description.isEmpty()) && publicKey != null) {
            entry.setDescription("SSH Public Key: " + publicKey);
        } else {
            entry.setDescription(description);
        }
        entry.setFolderFullName(folderFullName);

        try {
            EncryptedVariableService.getInstance().saveEntry(entry);
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
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);

        String nameParam = req.getParameter("name");
        String keySizeStr = req.getParameter("keySize");
        String commentParam = req.getParameter("comment");
        String descriptionParam = req.getParameter("description");
        String folderFullNameParam = req.getParameter("folderFullName");
        final String name = nameParam != null ? nameParam : "";
        final String comment = commentParam != null ? commentParam : "";
        final String description = descriptionParam != null ? descriptionParam : "";
        final String folderFullName = folderFullNameParam != null ? folderFullNameParam : "";
        int keySizeTmp = 4096;
        try { keySizeTmp = Integer.parseInt(keySizeStr); } catch (Exception e) {}
        final int keySize = keySizeTmp;

        // Validate variable name
        VariableNameValidator.ValidationResult validation = VariableNameValidator.validate(name);
        if (!validation.isValid()) {
            return errorResponse(validation.getErrorMessage());
        }

        // Check if entry already exists
        if (EncryptedVariableService.getInstance().entryExists(folderFullName, name)) {
            return errorResponse(Messages.EncryptedManagementLink_entryAlreadyExists(name));
        }

        // Validate key size
        if (keySize != 2048 && keySize != 3072 && keySize != 4096 && keySize != 8192) {
            return errorResponse(Messages.EncryptedManagementLink_invalidKeySize());
        }

        try {
            ModelEntry entry = SshKeyGenerator.generateKeyPairJsch(name, keySize, comment, description, folderFullName);
            EncryptedVariableService.getInstance().saveEntry(entry);
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
        String name = req.getParameter("name");
        String folderFullName = req.getParameter("folderFullName");
        if (name == null) name = "";
        if (folderFullName == null) folderFullName = "";

        // Verify permission for the folder
        if (!checkFolderPermission(folderFullName)) {
            return errorResponse(Messages.EncryptedManagementLink_noPermission());
        }

        ModelEntry existing = EncryptedVariableService.getInstance().getEntry(folderFullName, name);
        if (existing == null) {
            return errorResponse(Messages.EncryptedManagementLink_entryNotFound(name));
        }

        String value = req.getParameter("secretValue");
        String description = req.getParameter("description");
        if (value == null) value = "";
        if (description == null) description = "";

        if (!value.isEmpty()) {
            existing.setSecretValue(hudson.util.Secret.fromString(value));
        }
        existing.setDescription(description);

        if (existing.getType() == ModelEntry.EntryType.USERNAME_PASSWORD) {
            String username = req.getParameter("username");
            if (username == null) username = "";
            existing.setUsername(username);
        }

        try {
            EncryptedVariableService.getInstance().saveEntry(existing);
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
        String nameParam = req.getParameter("name");
        String folderFullNameParam = req.getParameter("folderFullName");
        final String name = nameParam != null ? nameParam : "";
        final String folderFullName = folderFullNameParam != null ? folderFullNameParam : "";

        // Verify permission for the folder
        if (!checkFolderPermission(folderFullName)) {
            return errorResponse(Messages.EncryptedManagementLink_noPermission());
        }

        try {
            boolean result = EncryptedVariableService.getInstance().deleteEntry(folderFullName, name);
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
     * Get decrypted value of an entry (AJAX endpoint).
     */
    @RequirePOST
    public HttpResponse doDecryptValue(StaplerRequest req) throws IOException, ServletException {
        String name = req.getParameter("name");
        String folderFullName = req.getParameter("folderFullName");
        if (name == null) name = "";
        if (folderFullName == null) folderFullName = "";

        if (!checkFolderPermission(folderFullName)) {
            return errorResponse(Messages.EncryptedManagementLink_noPermission());
        }

        ModelEntry entry = EncryptedVariableService.getInstance().getEntry(folderFullName, name);
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

    private boolean checkFolderPermission(String folderFullName) {
        Jenkins jenkins = Jenkins.get();
        Item item = jenkins.getItemByFullName(folderFullName);
        if (item == null) {
            return jenkins.hasPermission(Jenkins.ADMINISTER);
        }
        return item.hasPermission(Item.CONFIGURE);
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
}
