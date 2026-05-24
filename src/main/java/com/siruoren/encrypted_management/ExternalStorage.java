package com.siruoren.encrypted_management;

import net.sf.json.JSONObject;

import java.io.IOException;

/**
 * 外部存储后端接口
 * 解耦Jenkins配置，凭据可存储在外部系统
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
     * 保存凭据到外部存储
     * @param folderName 文件夹名
     * @param credentialId 凭据ID
     * @param credentialData 凭据数据（JSON格式）
     */
    void saveCredential(String folderName, String credentialId, JSONObject credentialData) throws IOException;

    /**
     * 从外部存储读取凭据
     * @param folderName 文件夹名
     * @param credentialId 凭据ID
     * @return 凭据数据（JSON格式），不存在返回null
     */
    JSONObject loadCredential(String folderName, String credentialId) throws IOException;

    /**
     * 从外部存储删除凭据
     * @param folderName 文件夹名
     * @param credentialId 凭据ID
     */
    void deleteCredential(String folderName, String credentialId) throws IOException;

    /**
     * 列出指定文件夹的所有凭据ID
     * @param folderName 文件夹名
     * @return 凭据ID列表
     */
    java.util.List<String> listCredentials(String folderName) throws IOException;

    /**
     * 获取存储后端配置信息（不包含敏感信息）
     */
    JSONObject getConfigInfo();
}
