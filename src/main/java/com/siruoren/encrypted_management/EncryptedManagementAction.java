package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.common.IdCredentials;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernameCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import hudson.Extension;
import hudson.model.Action;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.security.Permission;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 凭据管理页面 Action
 * 自动读取当前文件夹的所有原生凭据，支持创建/删除
 * 凭据类型完全兼容Jenkins原生凭据系统
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
     * 获取当前文件夹的凭据存储
     */
    private CredentialsStore getFolderStore() {
        for (CredentialsStore store : CredentialsProvider.lookupStores(folder)) {
            if (store.getContext() == folder) {
                return store;
            }
        }
        return null;
    }

    /**
     * API: 以JSON格式返回当前文件夹的所有凭据（页面自动加载）
     */
    public HttpResponse doListCredentials(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        JSONArray arr = new JSONArray();
        List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) folder, null, Collections.emptyList());

        for (StandardCredentials c : creds) {
            JSONObject obj = new JSONObject();
            obj.put("id", c.getId());
            obj.put("name", c.getDescription() != null ? c.getDescription() : c.getId());
            obj.put("type", getCredentialsTypeName(c));
            obj.put("typeKey", getCredentialsTypeKey(c));

            if (c instanceof UsernamePasswordCredentials) {
                obj.put("username", ((UsernamePasswordCredentials) c).getUsername());
            }

            arr.add(obj);
        }

        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("credentials", arr);
        result.put("folder", folder.getFullName());
        result.put("count", creds.size());

        return jsonResult(result);
    }

    /**
     * API: 解密指定凭据的值
     */
    @RequirePOST
    public HttpResponse doDecryptCredential(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                StandardCredentials.class, (ItemGroup<?>) folder, null, Collections.emptyList());

        for (StandardCredentials c : creds) {
            if (c.getId().equals(id)) {
                JSONObject result = new JSONObject();
                result.put("success", true);
                result.put("id", id);
                result.put("type", getCredentialsTypeName(c));
                result.put("typeKey", getCredentialsTypeKey(c));

                if (c instanceof UsernamePasswordCredentials) {
                    UsernamePasswordCredentials upc = (UsernamePasswordCredentials) c;
                    result.put("username", upc.getUsername());
                    result.put("password", Secret.toString(upc.getPassword()));
                } else if (c instanceof StringCredentials) {
                    result.put("secret", Secret.toString(((StringCredentials) c).getSecret()));
                }

                return jsonResult(result);
            }
        }

        return errorResponse("Credential not found: " + id);
    }

    /**
     * API: 创建Secret Text凭据
     */
    @RequirePOST
    public HttpResponse doCreateSecretText(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String secret = req.getParameter("secret");

        if (secret == null || secret.trim().isEmpty()) {
            return errorResponse("Secret value is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
        }

        try {
            StringCredentialsImpl credential = new StringCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    Secret.fromString(secret));

            store.addCredentials(Domain.global(), credential);
            return successResponse("Secret text credential created successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create secret text credential", e);
            return errorResponse("Failed to create credential: " + e.getMessage());
        }
    }

    /**
     * API: 创建Username/Password凭据
     */
    @RequirePOST
    public HttpResponse doCreateUsernamePassword(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        String description = req.getParameter("description");
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        if (username == null || username.trim().isEmpty()) {
            return errorResponse("Username is required");
        }
        if (password == null || password.trim().isEmpty()) {
            return errorResponse("Password is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
        }

        try {
            UsernamePasswordCredentialsImpl credential = new UsernamePasswordCredentialsImpl(
                    CredentialsScope.GLOBAL,
                    (id != null && !id.isEmpty()) ? id : null,
                    description,
                    username,
                    password);

            store.addCredentials(Domain.global(), credential);
            return successResponse("Username/Password credential created successfully");
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to create username/password credential", e);
            return errorResponse("Failed to create credential: " + e.getMessage());
        }
    }

    /**
     * API: 删除凭据
     */
    @RequirePOST
    public HttpResponse doDeleteCredential(StaplerRequest req, StaplerResponse rsp) throws IOException {
        folder.checkPermission(Item.CONFIGURE);

        String id = req.getParameter("id");
        if (id == null || id.isEmpty()) {
            return errorResponse("Credential ID is required");
        }

        CredentialsStore store = getFolderStore();
        if (store == null) {
            return errorResponse("No credentials store found for this folder");
        }

        try {
            // Find the credential by ID
            List<StandardCredentials> creds = CredentialsProvider.lookupCredentials(
                    StandardCredentials.class, (ItemGroup<?>) folder, null, Collections.emptyList());

            for (StandardCredentials c : creds) {
                if (c.getId().equals(id)) {
                    boolean removed = store.removeCredentials(Domain.global(), c);
                    if (removed) {
                        return successResponse("Credential deleted successfully");
                    } else {
                        return errorResponse("Failed to remove credential from store");
                    }
                }
            }
            return errorResponse("Credential not found: " + id);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to delete credential", e);
            return errorResponse("Failed to delete credential: " + e.getMessage());
        }
    }

    private String getCredentialsTypeName(StandardCredentials c) {
        if (c instanceof UsernamePasswordCredentials) {
            return "Username with password";
        } else if (c instanceof StringCredentials) {
            return "Secret text";
        }
        return c.getClass().getSimpleName();
    }

    private String getCredentialsTypeKey(StandardCredentials c) {
        if (c instanceof UsernamePasswordCredentials) {
            return "USERNAME_PASSWORD";
        } else if (c instanceof StringCredentials) {
            return "SECRET_TEXT";
        }
        return "OTHER";
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

    private HttpResponse errorResponse(String message) {
        JSONObject result = new JSONObject();
        result.put("success", false);
        result.put("message", message);
        return jsonResult(result);
    }

    private HttpResponse successResponse(String message) {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", message);
        return jsonResult(result);
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
