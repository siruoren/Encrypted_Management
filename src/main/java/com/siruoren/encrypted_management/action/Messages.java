package com.siruoren.encrypted_management.action;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Localized messages for EncryptedManagementLink.
 */
public class Messages {

    public static String EncryptedManagementLink_displayName() {
        return "Encrypted Management";
    }

    public static String EncryptedManagementLink_description() {
        return "Manage encrypted variables and SSH key pairs for folder tasks";
    }

    public static String EncryptedManagementLink_entryAlreadyExists(@NonNull String name) {
        return "Encrypted variable '" + name + "' already exists";
    }

    public static String EncryptedManagementLink_invalidType() {
        return "Invalid variable type";
    }

    public static String EncryptedManagementLink_useSshKeyGenerator() {
        return "SSH key pairs must be generated using the SSH key generator";
    }

    public static String EncryptedManagementLink_saveFailed(@NonNull String reason) {
        return "Failed to save: " + reason;
    }

    public static String EncryptedManagementLink_entryCreated(@NonNull String name) {
        return "Encrypted variable '" + name + "' created successfully";
    }

    public static String EncryptedManagementLink_invalidKeySize() {
        return "Invalid key size. Supported sizes: 2048, 3072, 4096, 8192";
    }

    public static String EncryptedManagementLink_sshKeyGenerated(@NonNull String name) {
        return "SSH key pair '" + name + "' generated successfully";
    }

    public static String EncryptedManagementLink_sshKeyGenFailed(@NonNull String reason) {
        return "Failed to generate SSH key pair: " + reason;
    }

    public static String EncryptedManagementLink_noPermission() {
        return "You do not have permission to perform this action";
    }

    public static String EncryptedManagementLink_entryNotFound(@NonNull String name) {
        return "Encrypted variable '" + name + "' not found";
    }

    public static String EncryptedManagementLink_entryUpdated(@NonNull String name) {
        return "Encrypted variable '" + name + "' updated successfully";
    }

    public static String EncryptedManagementLink_updateFailed(@NonNull String reason) {
        return "Failed to update: " + reason;
    }

    public static String EncryptedManagementLink_entryDeleted(@NonNull String name) {
        return "Encrypted variable '" + name + "' deleted successfully";
    }

    public static String EncryptedManagementLink_deleteFailed(@NonNull String reason) {
        return "Failed to delete: " + reason;
    }

    public static String FolderAction_displayName() {
        return "Encrypted Variables";
    }

    public static String FolderAction_iconFileName() {
        return "symbol-encrypted-folder";
    }
}
