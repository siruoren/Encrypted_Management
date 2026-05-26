# Changelog

All notable changes to the Encrypted Management plugin will be documented in this file.

## [1.0.1-SNAPSHOT] - 2026-05-26

### Added

- **凭据选择导出/导入**：导出凭据弹窗支持选择要导出的凭据（默认不选择），导入凭据弹窗分为两步：先解析数据展示凭据列表（默认全选），再选择要导入的凭据。支持按凭据 ID 筛选导出、按凭据索引筛选导入

- **ZIP 导入流程优化**：全量导入 ZIP 弹窗分为两步：先解析 ZIP 展示所有凭据（按目录分组，默认全选），再选择要导入的凭据；冲突处理从复选框改为单选按钮，支持"跳过已存在的凭据"（默认）和"强制覆盖已存在的凭据"

- **文件夹凭据管理凭据选择**：目录任务下的凭据导出/导入弹窗同样支持凭据选择和两步导入流程

- **导入速度优化与线程管理**：新增 `ImportService` 统一导入服务，使用线程池并发导入提升批量导入速度；ZIP 全量导入时各条目并行处理；使用 daemon 线程防止内存泄露

- **导入结果详细展示**：所有导入操作完成后弹出结果统计弹窗，展示新增、覆盖、跳过、失败四种状态的数量和详细列表

- **代码架构优化**：导入逻辑从 Action 层解耦到 `ImportService`，便于后期维护和扩展

### Changed

- **外部存储功能精简**：移除目录任务（Folder）级别的外部存储功能，仅保留系统凭据管理（Jenkins 根目录）下的外部存储功能，减少凭据扩散风险，降低攻击面

- **审计日志功能精简**：移除目录任务下的审计日志查看和配置功能，仅保留系统凭据管理下的审计日志功能，审计日志条目按时间倒序排列

- **审计日志持久化**：审计日志写入线程改为非 daemon 线程，注册 JVM shutdown hook 确保关闭时不丢失日志

- **加密代码去重**：将 `CredentialBackupService` 和 `FileExternalStorage` 中重复的 AES-256-GCM 加密/解密/PBKDF2 密钥派生代码提取到 `CryptoService` 统一管理

- **异常信息脱敏**：所有通用异常捕获不再向前端返回 `e.getMessage()`，改为返回通用错误提示，详细信息仅记录在服务端日志

- **XSS 防护完善**：所有返回前端的用户可控字段（id、description、username 等）统一调用 `CredentialService.escapeHtml()` 进行转义

### Security

- **权限模型增强**：解密、导出、同步等敏感操作升级为 `Jenkins.ADMINISTER` 权限，防止低权限用户获取明文凭据

- **Zip Slip 漏洞修复**：对 ZIP 条目路径进行规范化检查，拒绝包含 `..` 或绝对路径的恶意条目

- **密码安全管理**：外部存储密码从 `String` 改为 `char[]`，使用后及时用 `Arrays.fill()` 擦除，防止 Heap Dump 泄露

- **加密密钥与 Jenkins master.key 绑定**：PBKDF2 密钥派生混入 Jenkins master.key，防止导出文件被离线暴力破解

- **JSON Schema 验证**：新增凭据类型白名单、字段白名单和长度校验，防止反序列化攻击和数据污染

- **审计日志脱敏**：credentialId 和 folder 使用 SHA-256 哈希摘要记录，避免泄露内部系统命名

- **导入限流**：ZIP 文件大小限制 20MB，单次导入凭据数量限制 1000 条

- **线程池生命周期管理**：使用 `@Terminator` 在 Jenkins 关闭时优雅关闭所有线程池，防止 ClassLoader 泄露

## [1.0.1] - 2026-05-25

### Added

- **目录任务凭据分层存储**：Jenkins 根目录下额外加密存储支持按目录层级保存凭据，以目录任务的 `fullName` 路径作为子目录结构，保持与 Jenkins 目录任务层级一致

- **全量 ZIP 导入导出**：Jenkins 首页「系统凭证管理」支持导入导出所有目录任务的凭据并打包为 ZIP 包
  - ZIP 包结构与 Jenkins 目录任务路径保持一致
  - 导出时使用 AES-256-GCM 加密保护
  - 导入时自动按层级结构恢复到对应目录任务
  - 支持覆盖现有凭据选项

### Fixed

- **文件夹凭据列表泄露系统级凭据**：修复目录任务下的凭证列表除了显示当前目录任务的凭据外，还错误地显示了 Jenkins 系统级凭据的问题。`CredentialsProvider.lookupCredentials()` 会递归返回父级凭据，现改为直接从文件夹自身的 `CredentialsStore` 获取凭据，确保只显示当前文件夹存储的凭据。影响范围：凭据列表、凭据查找、凭据导出、外部存储同步

## [1.0.0] - 2025-05-25

### Added

- **凭据管理核心功能**
  - 支持 Secret Text、Username with Password、SSH Username with Private Key 三种凭据类型
  - 创建、解密查看、更新、删除凭据
  - SSH 密钥对一键生成（RSA 2048），支持 passphrase 加密私钥
  - 解密 SSH 凭据时自动推导并显示 OpenSSH 格式公钥
  - 权限控制：仅 Configure 权限用户可操作
  - 国际化：中英文切换

- **独立审计日志系统**
  - 脱离 Jenkins 审计体系，独立文件存储（`JENKINS_HOME/encrypted-management-audit/`）
  - 按日期轮转，单文件 50MB 上限
  - 保留天数可在页面配置（默认 30 天）
  - 记录所有凭据操作（CREATE/READ/UPDATE/DELETE/EXPORT/IMPORT/SYNC 等）

- **凭据加密备份/导入**
  - AES-256-GCM 加密导出，PBKDF2 密钥派生（65536 迭代）
  - 支持导出为文本（页面内复制）或下载为加密文件（`.enc`）
  - 支持从粘贴内容或上传备份文件导入
  - 解决 Master 单点故障问题

- **外部存储解耦**
  - 定义 `ExternalStorage` 接口，实现 `FileExternalStorage` 文件系统后端
  - 支持 Manual / Auto Sync / External Only 三种同步模式
  - 支持自定义存储路径
  - 每个目录任务的所有凭据保存为一个 JSON 文件，系统级凭据使用 `jenkins_root.json`
  - 外部存储文件强制加密存储，加密密码为必填项
  - 支持从外部存储 JSON 文件直接导入凭据到 Jenkins
  - 凭据写入使用临时文件+原子重命名，防止数据损坏

- **REST API**
  - 审计日志查询/配置 API
  - 凭据导出/导入 API（文本和文件两种方式）
  - 外部存储状态/配置/同步/连接测试 API

- **弹窗交互**
  - 所有操作改为弹窗形式（创建/更新凭据、审计日志、导出/导入、外部存储配置）
  - 错误信息统一弹窗提示
  - 解密内容通过独立弹窗显示

- **并发优化**
  - 审计日志：单线程 Executor 异步写入，不阻塞调用线程
  - 外部存储管理器：ReadWriteLock 保护配置原子性变更
  - 文件存储：per-folder 细粒度 ReentrantLock，避免全局锁阻塞
  - 同步操作：异步非阻塞执行，有限线程池（CPU 核心数），守护线程防内存泄露
  - volatile 保证共享变量可见性

- **Swagger 风格 API 文档**
  - 独立 API 文档页面，Swagger 标准布局和配色
  - 按模块分组展示：凭证管理、审计日志、备份恢复、外部存储
  - 每个端点显示方法、路径、参数表、响应示例
  - Schema 模型展示区，定义 ApiResponse、Credential、ImportResult、StorageStatus 数据结构
  - "Try it" 在线测试功能，支持参数输入、实时调用 API 并展示 JSON 响应
  - 自动生成带 Jenkins Crumb 的 Curl 命令，方便命令行调试
  - 文件上传支持（FileReader 读取文件内容到文本框）
  - 文件下载支持（表单提交触发浏览器下载）
  - 主页面右上角 API 文档跳转按钮
  - API 文档页面中英文国际化支持

- **Jenkins 根目录系统级凭据管理**
  - 新增 SystemCredentialsAction，管理员在 Jenkins 首页左侧菜单可见「系统凭证管理」
  - 与文件夹级凭据管理功能完全一致：增删改查、SSH密钥生成、审计日志、备份导入导出、外部存储
  - 仅管理员（ADMINISTER 权限）可见和操作
  - 独立的 Swagger API 文档页面
  - 中英文国际化支持

### Fixed

- 移除未使用的依赖（structs、jsch），优化项目依赖结构

### Tests

- 添加单元测试（25个测试用例）
  - CredentialBackupServiceTest：AES-256-GCM 加密解密测试、JSON 数据结构测试、特殊字符/中文字符/长文本加密测试
  - FileExternalStorageTest：连接测试、保存/加载凭据测试、系统级凭据文件命名测试、路径清理安全测试、强制加密密码测试
