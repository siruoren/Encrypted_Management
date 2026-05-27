# Changelog

All notable changes to the Encrypted Management plugin will be documented in this file.

## [1.0.0] - 2025-05-27

### Added

- **凭据管理核心功能**
  - 支持 Secret Text、Username with Password、SSH Username with Private Key 三种凭据类型
  - 提供凭据的创建、解密查看、更新、删除完整生命周期管理
  - SSH 密钥对一键生成（RSA 2048），支持 passphrase 加密私钥
  - 解密 SSH 凭据时自动推导并显示 OpenSSH 格式公钥
  - 权限控制：仅 Configure 权限用户可操作
  - 完整的国际化支持（中英文切换）

- **独立审计日志系统**
  - 脱离 Jenkins 审计体系，采用独立文件存储（`JENKINS_HOME/encrypted-management-audit/`）
  - 按日期轮转，单文件 50MB 上限
  - 保留天数可在页面配置（默认 30 天）
  - 记录所有凭据操作（CREATE/READ/UPDATE/DELETE/EXPORT/IMPORT 等）

- **凭据加密备份/导入**
  - AES-256-GCM 加密导出，PBKDF2 密钥派生（65536 迭代）
  - 支持导出为文本（页面内复制）或下载为加密文件（`.enc`）
  - 支持从粘贴内容或上传备份文件导入
  - 解决 Master 单点故障问题

- **REST API**
  - 审计日志查询/配置 API
  - 凭据导出/导入 API（文本和文件两种方式）

- **弹窗交互优化**
  - 所有操作改为弹窗形式（创建/更新凭据、审计日志、导出/导入）
  - 错误信息统一弹窗提示
  - 解密内容通过独立弹窗显示

- **并发优化**
  - 审计日志：单线程 Executor 异步写入，不阻塞调用线程
  - 文件存储：per-folder 细粒度 ReentrantLock，避免全局锁阻塞
  - volatile 保证共享变量可见性

- **Swagger 风格 API 文档**
  - 独立 API 文档页面，Swagger 标准布局和配色
  - 按模块分组展示：凭证管理、审计日志、备份恢复
  - 每个端点显示方法、路径、参数表、响应示例
  - Schema 模型展示区，定义 ApiResponse、Credential、ImportResult 数据结构
  - "Try it" 在线测试功能，支持参数输入、实时调用 API 并展示 JSON 响应
  - 自动生成带 Jenkins Crumb 的 Curl 命令，方便命令行调试
  - 文件上传/下载支持
  - API 文档页面中英文国际化支持

- **Jenkins 根目录系统级凭据管理**
  - 新增 SystemCredentialsAction，管理员在 Jenkins 首页左侧菜单可见「系统凭证管理」
  - 与文件夹级凭据管理功能完全一致：增删改查、SSH 密钥生成、审计日志、备份导入导出
  - 仅管理员（ADMINISTER 权限）可见和操作
  - 独立的 Swagger API 文档页面
  - 中英文国际化支持

### Changed

- **优化按钮布局**：系统凭证管理页面将审计日志按钮移至操作按钮最后位置，保持主要操作（创建、导出、导入）靠前显示

### Fixed

- **修复凭据导出空指针异常**：当凭据的 `getScope()` 返回 null 时，导出操作会抛出 `NullPointerException`，现已添加空值保护，默认使用 `GLOBAL` 作用域
- **修复审计日志排序问题**：审计日志条目未按时间倒序排列，现已修正文件读取顺序，确保最新的日志条目显示在最前面
- **修复操作后列表更新不及时**：创建、更新、删除凭据后使用整页 `reload()` 刷新，现已改为调用 `loadCredentials()` 仅刷新凭据列表，操作后立即生效
- **修复文件夹凭据列表泄露系统级凭据**：目录任务下的凭证列表错误地显示了 Jenkins 系统级凭据，现改为直接从文件夹自身的 `CredentialsStore` 获取凭据，确保只显示当前文件夹存储的凭据
- **移除未使用的依赖**：移除 structs、jsch 依赖，优化项目依赖结构

### Removed

- **移除外部存储功能**：移除所有外部存储相关代码和 UI，包括 `ExternalStorage` 接口、`ExternalStorageManager` 管理器、`FileExternalStorage` 文件系统实现及其单元测试；移除两个页面的外部存储按钮、配置弹窗和 JavaScript 逻辑；移除 API 文档中的外部存储 API 端点和 StorageConfig 数据模型；移除所有外部存储相关 i18n 键
- **移除文件夹页面审计日志功能**：审计日志仅在系统凭证管理页面提供，文件夹凭据管理页面不再显示审计日志按钮和弹窗，避免功能冗余

### Tests

- **添加单元测试（25 个测试用例）**
  - CredentialBackupServiceTest：AES-256-GCM 加密解密测试、JSON 数据结构测试、特殊字符/中文字符/长文本加密测试
  - FileExternalStorageTest：连接测试、保存/加载凭据测试、系统级凭据文件命名测试、路径清理安全测试、强制加密密码测试
