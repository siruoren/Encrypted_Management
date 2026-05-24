package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Item;
import hudson.security.Permission;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 加密变量管理页面 Action，提供查看、解密、创建加密变量的功能
 */
public class EncryptedManagementAction implements Action {
    private static final Logger LOGGER = Logger.getLogger(EncryptedManagementAction.class.getName());

    private final Folder folder;

    public EncryptedManagementAction(@Nonnull Folder folder) {
        this.folder = folder;
    }

    @Override
    public String getIconFileName() {
        return "symbol-lock plugin-encrypted-management";
    }

    @Override
    public String getDisplayName() {
        return Messages.EncryptedManagementAction_DisplayName();
    }

    @Override
    public String getUrlName() {
        return "encrypted-variables";
    }

    public Folder getFolder() {
        return folder;
    }

    /**
     * 获取当前文件夹的加密变量列表
     */
    public List<EncryptedVariable> getVariables() {
        FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
        if (property != null) {
            return property.getVariables();
        }
        return Collections.emptyList();
    }

    /**
     * 解密指定索引的加密变量，使用线程池异步执行
     */
    @RequirePOST
    public void doDecrypt(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String indexStr = req.getParameter("index");
        if (indexStr == null || indexStr.isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Index parameter is required");
            return;
        }

        int index;
        try {
            index = Integer.parseInt(indexStr);
        } catch (NumberFormatException e) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Invalid index format");
            return;
        }

        FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
        if (property == null) {
            sendError(rsp, HttpServletResponse.SC_NOT_FOUND, "No encrypted variables found");
            return;
        }

        EncryptedVariable variable = property.getVariable(index);
        if (variable == null) {
            sendError(rsp, HttpServletResponse.SC_NOT_FOUND, "Variable not found at index: " + index);
            return;
        }

        // 使用线程池异步解密，防止阻塞
        ExecutorService executor = ThreadPoolManager.getInstance().getExecutor();
        Future<String> future = executor.submit((Callable<String>) () -> {
            Secret secret = variable.getValue();
            return secret != null ? Secret.toString(secret) : "";
        });

        String plainText;
        try {
            plainText = future.get();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to decrypt variable", e);
            sendError(rsp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Decryption failed");
            return;
        }

        rsp.setContentType("application/json;charset=UTF-8");
        rsp.getWriter().write("{\"success\":true,\"plainText\":\"" + escapeJson(plainText) + "\"}");
    }

    /**
     * 创建新的加密变量并写入当前文件夹配置，然后 reload
     */
    @RequirePOST
    public void doCreate(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String name = req.getParameter("name");
        String value = req.getParameter("value");

        if (name == null || name.trim().isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Variable name is required");
            return;
        }
        if (value == null || value.trim().isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Variable value is required");
            return;
        }

        // 使用线程池异步执行创建操作
        ExecutorService executor = ThreadPoolManager.getInstance().getExecutor();
        Future<Boolean> future = executor.submit((Callable<Boolean>) () -> {
            try {
                FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
                if (property == null) {
                    property = new FolderEncryptedProperty();
                    folder.addProperty(property);
                }

                // 检查同名变量是否已存在
                EncryptedVariable existing = property.findVariable(name.trim());
                if (existing != null) {
                    return false;
                }

                // 创建加密变量
                EncryptedVariable newVar = new EncryptedVariable(name.trim(), Secret.fromString(value));
                property.addVariable(newVar);

                // 保存文件夹配置
                property.saveFolderConfig();
                return true;
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to create encrypted variable", e);
                return false;
            }
        });

        boolean success;
        try {
            success = future.get();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create encrypted variable", e);
            sendError(rsp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Creation failed");
            return;
        }

        if (!success) {
            rsp.setContentType("application/json;charset=UTF-8");
            rsp.getWriter().write("{\"success\":false,\"message\":\"Variable with this name already exists\"}");
            return;
        }

        rsp.setContentType("application/json;charset=UTF-8");
        rsp.getWriter().write("{\"success\":true,\"message\":\"Variable created successfully\"}");
    }

    /**
     * 删除指定名称的加密变量
     */
    @RequirePOST
    public void doDelete(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String name = req.getParameter("name");
        if (name == null || name.trim().isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Variable name is required");
            return;
        }

        ExecutorService executor = ThreadPoolManager.getInstance().getExecutor();
        Future<Boolean> future = executor.submit((Callable<Boolean>) () -> {
            try {
                FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
                if (property == null) {
                    return false;
                }
                boolean removed = property.removeVariable(name.trim());
                if (removed) {
                    property.saveFolderConfig();
                }
                return removed;
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to delete encrypted variable", e);
                return false;
            }
        });

        boolean success;
        try {
            success = future.get();
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to delete encrypted variable", e);
            sendError(rsp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Deletion failed");
            return;
        }

        rsp.setContentType("application/json;charset=UTF-8");
        rsp.getWriter().write("{\"success\":" + success + "}");
    }

    private void sendError(StaplerResponse rsp, int code, String message) throws IOException {
        rsp.setContentType("application/json;charset=UTF-8");
        rsp.setStatus(code);
        rsp.getWriter().write("{\"success\":false,\"message\":\"" + escapeJson(message) + "\"}");
    }

    private String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * 通过 TransientActionFactory 自动为所有 Folder 添加此 Action
     */
    @Extension
    public static class ActionFactory extends TransientActionFactory<Folder> {
        @Override
        public Class<Folder> type() {
            return Folder.class;
        }

        @Override
        @Nonnull
        public Collection<? extends Action> createFor(@Nonnull Folder folder) {
            return Collections.singletonList(new EncryptedManagementAction(folder));
        }
    }
}
