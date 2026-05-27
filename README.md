# Encrypted Management

Jenkins 凭据管理插件 - 提供可视化的凭据管理界面，完全兼容 Jenkins 原生凭据系统，解决凭据与 Jenkins 配置耦合、审计缺失、单点故障、无原生集成等架构问题。

## 功能特性

- **凭据类型支持**：Secret Text、Username with Password、SSH Username with Private Key
- **自动加载**：打开页面自动加载当前文件夹的所有凭据
- **CRUD 操作**：创建、解密查看、更新、删除凭据
- **密钥对生成**：SSH 凭据支持一键生成 RSA 2048 密钥对，自动填充私钥和公钥
- **Passphrase 加密**：生成密钥对时如有 passphrase，自动使用 AES-128-CBC 加密私钥
- **公钥推导**：解密 SSH 凭据时自动从私钥推导并显示 OpenSSH 格式公钥
- **权限控制**：仅对有 Configure 权限的用户显示菜单和操作按钮，防止跨用户信息泄露
- **系统级凭据管理**：管理员在 Jenkins 根目录左侧菜单可见「系统凭证管理」，可增删改查 Jenkins 系统级凭据
- **国际化**：支持中英文切换
- **独立审计日志**：脱离 Jenkins 审计体系，独立记录所有凭据操作，按日期轮转，支持查看和清理（仅系统凭证管理页面可用）
- **凭据加密备份**：AES-256-GCM 加密导出，PBKDF2 密钥派生，支持跨 Jenkins 实例导入恢复，支持文件下载导出和文件上传导入
- **REST API**：提供审计日志、备份导入导出等 API，便于外部系统集成
- **Swagger API 文档**：独立 Swagger 风格 API 文档页面，按模块分组展示所有端点，支持在线测试（Try it）、Curl 命令生成、Schema 模型展示，主页面右上角可跳转
- **弹窗交互**：所有操作（创建/更新凭据、审计日志、导出/导入）均通过弹窗完成，错误信息统一弹窗提示
- **即时刷新**：操作完成后自动刷新凭据列表，无需整页重载

## 使用方式

1. 在 Jenkins Folder 页面左侧菜单点击「凭据管理」
2. 管理员在 Jenkins 根目录左侧菜单点击「系统凭证管理」可管理全局凭据
3. 页面自动加载当前范围内的所有凭据
4. 点击「添加凭据」弹窗中选择类型并填写信息
5. SSH 凭据可点击「生成密钥对」自动生成 RSA 密钥对
6. 点击「解密」查看凭据详情，SSH 凭据会同时显示公钥
7. 点击「更新」弹窗修改凭据内容，点击「删除」移除凭据
8. 点击「导出凭据」弹窗输入加密密码，可选择导出为文本或下载为加密文件
9. 点击「导入凭据」弹窗输入密码，可选择粘贴加密数据或上传备份文件导入
10. 系统凭证管理页面点击「审计日志」弹窗查看所有凭据操作记录，可设置最大保留天数
11. 点击页面右上角「API 文档」按钮进入 Swagger 风格 API 文档页面，可查看所有 API 端点详情并在线测试

## 权限要求

- 文件夹级凭据管理：需要 Folder 的 Configure 权限
- 系统级凭据管理（Jenkins 根目录）：需要 Jenkins ADMINISTER 权限（仅管理员可见左侧菜单）
- 所有操作（创建、解密、更新、删除）均需通过权限校验

## 版本历史

### v1.0.0 - 2025-05-27

#### Fixed

- **修复凭据导出空指针异常**：当凭据的 `getScope()` 返回 null 时导出报错，现已添加空值保护，默认使用 `GLOBAL` 作用域
- **修复审计日志排序**：审计日志条目按时间倒序排列，最新记录显示在最前面
- **修复操作后列表更新不及时**：创建/更新/删除凭据后改为刷新列表而非整页重载
- **修复文件夹凭据列表泄露系统级凭据**：目录任务下的凭证列表错误地显示了 Jenkins 系统级凭据，现改为直接从文件夹自身的 `CredentialsStore` 获取凭据，确保只显示当前文件夹存储的凭据

#### Removed

- **移除外部存储功能**：移除所有外部存储相关代码、UI 和 API
- **移除文件夹页面审计日志**：审计日志仅在系统凭证管理页面提供

#### Changed

- **优化按钮布局**：系统凭证管理页面将审计日志按钮移至操作按钮最后位置

### v0.1.0 - 2025-05-25

#### Added

- **凭据管理核心功能**：创建、解密查看、更新、删除凭据
- **凭据类型支持**：Secret Text、Username with Password、SSH Username with Private Key
- **SSH 密钥对生成**：支持 passphrase 加密私钥
- **公钥推导**：解密 SSH 凭据时自动显示公钥
- **权限控制**：仅 Configure 权限用户可操作
- **国际化**：中英文切换

#### Added (System Credentials)

- **Jenkins 根目录系统级凭据管理**：管理员在 Jenkins 首页左侧菜单可见「系统凭证管理」，支持增删改查系统级凭据，仅 ADMINISTER 权限可见

#### Added (Audit Log)

- **独立审计日志系统**：脱离 Jenkins 审计，独立文件存储（`JENKINS_HOME/encrypted-management-audit/`），按日期轮转，单文件 50MB 上限，保留天数可页面配置

#### Added (Backup & Restore)

- **凭据加密备份/导入**：AES-256-GCM 加密，PBKDF2 密钥派生，支持跨实例恢复，支持文件下载导出和文件上传导入，解决 Master 单点故障问题

#### Added (API)

- **REST API**：审计日志查询/配置、凭据导出/导入（文本和文件）等 API
- **Swagger API 文档**：独立 Swagger 风格 API 文档页面，按模块分组展示（凭证管理、审计日志、备份恢复），支持 Try it 在线测试、Curl 命令生成、Schema 模型展示、文件上传/下载测试

#### Changed

- **弹窗交互重构**：所有操作改为弹窗形式（创建/更新凭据、审计日志、导出/导入），错误信息统一弹窗提示

#### Added (Tests)

- **单元测试**：加密解密功能测试（25 个测试用例）

#### Changed

- **依赖优化**：移除未使用的依赖（structs、jsch），精简项目依赖结构


## Star History

[![Star History Chart](https://api.star-history.com/chart?repos=siruoren/encrypted_managaement&type=date&legend=top-left)](https://www.star-history.com/?repos=siruoren%2Fencrypted_managaement&type=date&legend=top-left)