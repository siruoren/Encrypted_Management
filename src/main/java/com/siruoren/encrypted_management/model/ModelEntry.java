package com.siruoren.encrypted_management.model;

import hudson.util.Secret;
import java.io.Serializable;

/**
 * Represents an encrypted variable entry stored under a folder task.
 */
public class ModelEntry implements Serializable {

    private static final long serialVersionUID = 1L;

    public enum EntryType {
        SECRET_TEXT,
        SECRET_FILE,
        SSH_KEY_PAIR,
        USERNAME_PASSWORD
    }

    private String name;
    private EntryType type;
    private Secret secretValue;
    private String description;
    private String sshPublicKey;
    private String username;
    private String folderFullName;
    private long createdTimestamp;
    private long updatedTimestamp;

    public ModelEntry() {
        this.createdTimestamp = System.currentTimeMillis();
        this.updatedTimestamp = this.createdTimestamp;
    }

    public ModelEntry(String name, EntryType type, Secret secretValue, String description, String folderFullName) {
        this.name = name;
        this.type = type;
        this.secretValue = secretValue;
        this.description = description;
        this.folderFullName = folderFullName;
        this.createdTimestamp = System.currentTimeMillis();
        this.updatedTimestamp = this.createdTimestamp;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public EntryType getType() {
        return type;
    }

    public void setType(EntryType type) {
        this.type = type;
    }

    public Secret getSecretValue() {
        return secretValue;
    }

    public void setSecretValue(Secret secretValue) {
        this.secretValue = secretValue;
    }

    public String getDecryptedValue() {
        return secretValue != null ? Secret.toString(secretValue) : null;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSshPublicKey() {
        return sshPublicKey;
    }

    public void setSshPublicKey(String sshPublicKey) {
        this.sshPublicKey = sshPublicKey;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getFolderFullName() {
        return folderFullName;
    }

    public void setFolderFullName(String folderFullName) {
        this.folderFullName = folderFullName;
    }

    public long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(long createdTimestamp) {
        this.createdTimestamp = createdTimestamp;
    }

    public long getUpdatedTimestamp() {
        return updatedTimestamp;
    }

    public void setUpdatedTimestamp(long updatedTimestamp) {
        this.updatedTimestamp = updatedTimestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ModelEntry that = (ModelEntry) o;
        if (name == null || that.name == null) return false;
        return name.equals(that.name);
    }

    @Override
    public int hashCode() {
        return name != null ? name.hashCode() : 0;
    }
}
