package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Item;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
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
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 凭据管理页面 Action，提供查看、解密、创建凭据的功能
 * 每次打开页面自动加载当前文件夹的所有凭证
 */
public class EncryptedManagementAction implements Action {
    private static final Logger LOGGER = Logger.getLogger(EncryptedManagementAction.class.getName());

    private final Folder folder;

    public EncryptedManagementAction(@Nonnull Folder folder) {
        this.folder = folder;
    }

    @Override
    public String getIconFileName() {
        return folder.hasPermission(Item.CONFIGURE) ? "symbol-credentials plugin-encrypted-management" : null;
    }

    @Override
    public String getDisplayName() {
        return Messages.EncryptedManagementAction_DisplayName();
    }

    @Override
    public String getUrlName() {
        return "Encrypted_Management";
    }

    public Folder getFolder() {
        return folder;
    }

    public String getFolderFullName() {
        return folder.getFullName();
    }

    /**
     * 获取当前文件夹的凭据列表（页面渲染时自动调用）
     */
    public List<EncryptedVariable> getVariables() {
        FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
        if (property != null) {
            return property.getVariables();
        }
        return Collections.emptyList();
    }

    /**
     * API: 以JSON格式返回当前文件夹的所有凭据（供前端AJAX自动加载）
     */
    public HttpResponse doListCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        List<EncryptedVariable> variables = getVariables();
        JSONArray arr = new JSONArray();
        for (int i = 0; i < variables.size(); i++) {
            EncryptedVariable v = variables.get(i);
            JSONObject obj = new JSONObject();
            obj.put("index", i);
            obj.put("name", v.getName());
            obj.put("encryptedValue", v.getEncryptedValue());
            arr.add(obj);
        }

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("credentials", arr);
        result.put("folder", folder.getFullName());
        result.put("count", variables.size());

        return new HttpResponse() {
            @Override
            public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException {
                rsp.setContentType("application/json;charset=UTF-8");
                rsp.getWriter().write(result.toString());
            }
        };
    }

    /**
     * 解密指定索引的凭据
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
            sendError(rsp, HttpServletResponse.SC_NOT_FOUND, "No credentials found");
            return;
        }

        EncryptedVariable variable = property.getVariable(index);
        if (variable == null) {
            sendError(rsp, HttpServletResponse.SC_NOT_FOUND, "Credential not found at index: " + index);
            return;
        }

        String plainText;
        try {
            Secret secret = variable.getValue();
            plainText = secret != null ? Secret.toString(secret) : "";
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to decrypt credential", e);
            sendError(rsp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Decryption failed");
            return;
        }

        rsp.setContentType("application/json;charset=UTF-8");
        rsp.getWriter().write("{\"success\":true,\"plainText\":\"" + escapeJson(plainText) + "\"}");
    }

    /**
     * 创建新的凭据并写入当前文件夹配置，然后 reload
     */
    @RequirePOST
    public void doCreate(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String name = req.getParameter("name");
        String value = req.getParameter("value");

        if (name == null || name.trim().isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Credential name is required");
            return;
        }
        if (value == null || value.trim().isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Credential value is required");
            return;
        }

        try {
            FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
            if (property == null) {
                property = new FolderEncryptedProperty();
                folder.addProperty(property);
            }

            // 检查同名凭据是否已存在
            EncryptedVariable existing = property.findVariable(name.trim());
            if (existing != null) {
                rsp.setContentType("application/json;charset=UTF-8");
                rsp.getWriter().write("{\"success\":false,\"message\":\"Credential with this name already exists\"}");
                return;
            }

            // 创建凭据
            EncryptedVariable newVar = new EncryptedVariable(name.trim(), Secret.fromString(value));
            property.addVariable(newVar);

            // 保存文件夹配置
            property.saveFolderConfig();

            rsp.setContentType("application/json;charset=UTF-8");
            rsp.getWriter().write("{\"success\":true,\"message\":\"Credential created successfully\"}");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create credential", e);
            sendError(rsp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Creation failed");
        }
    }

    /**
     * 删除指定名称的凭据
     */
    @RequirePOST
    public void doDelete(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String name = req.getParameter("name");
        if (name == null || name.trim().isEmpty()) {
            sendError(rsp, HttpServletResponse.SC_BAD_REQUEST, "Credential name is required");
            return;
        }

        try {
            FolderEncryptedProperty property = folder.getProperties().get(FolderEncryptedProperty.class);
            if (property == null) {
                rsp.setContentType("application/json;charset=UTF-8");
                rsp.getWriter().write("{\"success\":false}");
                return;
            }
            boolean removed = property.removeVariable(name.trim());
            if (removed) {
                property.saveFolderConfig();
            }
            rsp.setContentType("application/json;charset=UTF-8");
            rsp.getWriter().write("{\"success\":" + removed + "}");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to delete credential", e);
            sendError(rsp, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Deletion failed");
        }
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
