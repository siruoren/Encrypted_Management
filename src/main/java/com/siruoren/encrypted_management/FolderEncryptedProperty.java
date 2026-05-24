package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.hudson.plugins.folder.FolderProperty;
import com.cloudbees.hudson.plugins.folder.FolderPropertyDescriptor;
import hudson.Extension;
import hudson.model.Action;
import hudson.util.Secret;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 文件夹属性，用于存储和管理加密变量列表
 */
public class FolderEncryptedProperty extends FolderProperty<Folder> {
    private static final Logger LOGGER = Logger.getLogger(FolderEncryptedProperty.class.getName());

    private List<EncryptedVariable> variables;

    @DataBoundConstructor
    public FolderEncryptedProperty(List<EncryptedVariable> variables) {
        this.variables = variables != null ? new ArrayList<>(variables) : new ArrayList<>();
    }

    public FolderEncryptedProperty() {
        this.variables = new ArrayList<>();
    }

    public List<EncryptedVariable> getVariables() {
        return Collections.unmodifiableList(variables != null ? variables : new ArrayList<>());
    }

    /**
     * 添加加密变量，线程安全
     */
    public synchronized void addVariable(@Nonnull EncryptedVariable variable) {
        if (this.variables == null) {
            this.variables = new ArrayList<>();
        }
        this.variables.add(variable);
    }

    /**
     * 根据名称查找加密变量
     */
    public EncryptedVariable findVariable(@Nonnull String name) {
        if (variables == null) return null;
        return variables.stream()
                .filter(v -> name.equals(v.getName()))
                .findFirst()
                .orElse(null);
    }

    /**
     * 根据索引获取加密变量
     */
    public EncryptedVariable getVariable(int index) {
        if (variables == null || index < 0 || index >= variables.size()) {
            return null;
        }
        return variables.get(index);
    }

    /**
     * 删除加密变量，线程安全
     */
    public synchronized boolean removeVariable(@Nonnull String name) {
        if (this.variables == null) return false;
        return this.variables.removeIf(v -> name.equals(v.getName()));
    }

    /**
     * 保存文件夹配置
     */
    public void saveFolderConfig() {
        try {
            Folder folder = getOwner();
            if (folder != null) {
                folder.save();
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to save folder configuration", e);
        }
    }

    @Override
    public List<Action> getFolderActions() {
        Folder folder = getOwner();
        if (folder != null) {
            return Collections.singletonList(new EncryptedManagementAction(folder));
        }
        return Collections.emptyList();
    }

    @Extension
    @Symbol("encryptedVariables")
    public static class DescriptorImpl extends FolderPropertyDescriptor {
        @Override
        @Nonnull
        public String getDisplayName() {
            return Messages.FolderEncryptedProperty_DisplayName();
        }
    }
}
