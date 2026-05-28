package com.siruoren.encrypted_management;

import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.List;

/**
 * 外部存储后端接口
 * 解耦Jenkins配置，凭据可存储在外部系统
 *
 * 存储结构：每个凭据单独保存为一个加密文件
 * - 系统级: storageDir/jenkins_root/credId.enc
 * - 目录任务: storageDir/folderName/credId.enc
 */
public interface ExternalStorage {

    /**
     * 存储后端类型标识
     */
    String getType();

    /**
     * 测试连接
     */
    boolean testConnection() throws IOException;

    /**
     * 保存单个凭据为独立加密文件
     * @param folderName 文件夹名（系统级使用"system"或"jenkins_root"）
     * @param credentialId 凭据ID
     * @param credentialData 单个凭据数据（JSON格式）
     */
    void saveCredential(String folderName, String credentialId, JSONObject credentialData) throws IOException;

    /**
     * 从外部存储加载单个凭据
     * @param folderName 文件夹名
     * @param credentialId 凭据ID
     * @return 凭据数据（JSON格式），不存在返回null
     */
    JSONObject loadCredential(String folderName, String credentialId) throws IOException;

    /**
     * 从外部存储删除单个凭据文件
     * @param folderName 文件夹名
     * @param credentialId 凭据ID
     */
    void deleteCredential(String folderName, String credentialId) throws IOException;

    /**
     * 列出指定文件夹下的所有凭据ID
     * @param folderName 文件夹名
     * @return 凭据ID列表
     */
    List<String> listCredentialIds(String folderName) throws IOException;

    /**
     * 保存指定文件夹的所有凭据（兼容旧接口，内部循环调用saveCredential）
     * @param folderName 文件夹名（系统级使用"jenkins_root"）
     * @param allCredentialsData 所有凭据数据（JSON格式，包含credentials数组）
     * @deprecated 使用 saveCredential 逐个保存替代
     */
    @Deprecated
    void saveAllCredentials(String folderName, JSONObject allCredentialsData) throws IOException;

    /**
     * 从外部存储加载指定文件夹的所有凭据（兼容旧接口，内部循环调用loadCredential）
     * @param folderName 文件夹名（系统级使用"jenkins_root"）
     * @return 所有凭据数据（JSON格式），不存在返回null
     * @deprecated 使用 listCredentialIds + loadCredential 逐个加载替代
     */
    @Deprecated
    JSONObject loadAllCredentials(String folderName) throws IOException;

    /**
     * 从外部存储删除指定文件夹的所有凭据文件
     * @param folderName 文件夹名
     */
    void deleteAllCredentials(String folderName) throws IOException;

    /**
     * 列出外部存储中所有文件夹名
     * @return 文件夹名列表
     */
    List<String> listFolders() throws IOException;

    /**
     * 获取存储后端配置信息（不包含敏感信息）
     */
    JSONObject getConfigInfo();
}
