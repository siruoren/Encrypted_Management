package com.siruoren.encrypted_management;

import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.List;

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
     * 保存指定文件夹的所有凭据为一个JSON文件
     * @param folderName 文件夹名（系统级使用"jenkins_root"）
     * @param allCredentialsData 所有凭据数据（JSON格式，包含credentials数组）
     */
    void saveAllCredentials(String folderName, JSONObject allCredentialsData) throws IOException;

    /**
     * 从外部存储加载指定文件夹的所有凭据
     * @param folderName 文件夹名（系统级使用"jenkins_root"）
     * @return 所有凭据数据（JSON格式），不存在返回null
     */
    JSONObject loadAllCredentials(String folderName) throws IOException;

    /**
     * 从外部存储删除指定文件夹的凭据文件
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
