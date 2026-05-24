# Encrypted Management

Jenkins 凭据管理插件 - 提供可视化的凭据管理界面，完全兼容 Jenkins 原生凭据系统。

## 功能特性

- **凭据类型支持**：Secret Text、Username with Password、SSH Username with Private Key
- **自动加载**：打开页面自动加载当前文件夹的所有凭据
- **CRUD 操作**：创建、解密查看、更新、删除凭据
- **密钥对生成**：SSH 凭据支持一键生成 RSA 2048 密钥对，自动填充私钥和公钥
- **Passphrase 加密**：生成密钥对时如有 passphrase，自动使用 AES-128-CBC 加密私钥
- **公钥推导**：解密 SSH 凭据时自动从私钥推导并显示 OpenSSH 格式公钥
- **权限控制**：仅对有 Configure 权限的用户显示菜单和操作按钮，防止跨用户信息泄露
- **国际化**：支持中英文切换

## 使用方式

1. 在 Jenkins Folder 页面左侧菜单点击「凭据管理」
2. 页面自动加载当前文件夹的所有凭据
3. 点击「添加凭据」选择类型并填写信息
4. SSH 凭据可点击「生成密钥对」自动生成 RSA 密钥对
5. 点击「解密」查看凭据详情，SSH 凭据会同时显示公钥
6. 点击「更新」修改凭据内容，点击「删除」移除凭据

## 权限要求

- 需要 Folder 的 Configure 权限才能访问凭据管理页面
- 所有操作（创建、解密、更新、删除）均需通过权限校验

## 版本历史

### v1.0.0

- 凭据管理核心功能（创建、解密、更新、删除）
- 支持 Secret Text、Username with Password、SSH Username with Private Key
- SSH 密钥对生成（支持 passphrase 加密）
- 解密 SSH 凭据时显示公钥
- 权限控制（仅 Configure 权限用户可操作）
- 国际化（中英文）
- 线程池优化（并发非阻塞、防内存泄露）
