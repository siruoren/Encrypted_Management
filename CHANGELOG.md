# Changelog

All notable changes to the Encrypted Management plugin will be documented in this file.

## [1.0.1] - 2026-05-28

### Added

- **单凭据独立加密存储**：每个凭据单独保存为 `凭据id.enc` 文件，放在对应目录任务子目录下，便于单独管理和版本控制
  - 存储结构：`storageDir/folderName/credentialId.enc`
  - 系统级凭据：`storageDir/jenkins_root/credentialId.enc`
- **ZIP 导出新格式**：全量导出时每个凭据单独一个 `.enc` 文件，ZIP 结构为 `jenkins_root/db-password.enc`、`test/ssh-key.enc`、`dev/team/api-token.enc`
- **ZIP 导入新格式**：支持解析新的单凭据 `.enc` 文件格式，导入时可选择单个凭据进行恢复
- **新的存储接口方法**：`ExternalStorage` 接口新增 `saveCredential`、`loadCredential`、`deleteCredential`、`listCredentialIds` 方法
- **单凭据序列化**：`CredentialBackupService` 新增 `serializeCredential` 和 `buildSingleCredentialExportJson` 方法

### Changed

- **外部存储同步逻辑**：同步到外部存储时使用 `saveCredential` 逐个保存，而非批量保存
- **ZIP 解析逻辑**：`doParseZipData` 改为解析新格式（每个 `.enc` 文件对应一个凭据）
- **代码去重**：移除 `SystemCredentialsAction` 中重复的 `serializeCredential` 方法，统一使用 `CredentialBackupService.serializeCredential`
- **旧格式兼容**：`saveAllCredentials` 和 `loadAllCredentials` 标记为 `@Deprecated`，但保持向后兼容

### Tests

- **单元测试更新**：`FileExternalStorageTest` 更新为 22 个测试用例，覆盖单凭据存储的所有操作

## [1.0.0] - 2026-01-01

### Added

- **Secret file 和 Certificate 凭据类型支持**：新增 Secret file（文件凭据）和 Certificate（证书凭据）两种凭据类型的完整 CRUD 支持，包括创建、解密查看、更新、删除、导出和导入
- **凭据类型全量支持**：现在支持所有 5 种 Jenkins 常用凭据类型：Secret Text、Username with Password、SSH Username with Private Key、Secret file、Certificate
- **凭据选择导出/导入**：导出凭据弹窗支持选择要导出的凭据（默认不选择），导入凭据弹窗分为两步：先解析数据展示凭据列表（默认全选），再选择要导入的凭据。支持按凭据 ID 筛选导出、按凭据索引筛选导入
- **ZIP 导入流程优化**：全量导入 ZIP 弹窗分为两步：先解析 ZIP 展示所有凭据（按目录分组，默认全选），再选择要导入的凭据；冲突处理支持"跳过已存在的凭据"（默认）和"强制覆盖已存在的凭据"
- **文件夹凭据管理凭据选择**：目录任务下的凭据导出/导入弹窗同样支持凭据选择和两步导入流程
- **导入速度优化与线程管理**：新增 `ImportService` 统一导入服务，使用线程池并发导入提升批量导入速度；ZIP 全量导入时各条目并行处理；使用 daemon 线程防止内存泄露
- **导入结果详细展示**：所有导入操作完成后弹出结果统计弹窗，展示新增、覆盖、跳过、失败四种状态的数量和详细列表
- **代码架构优化**：导入逻辑从 Action 层解耦到 `ImportService`，便于后期维护和扩展

### Changed

- **国际化 key 格式统一**：所有 i18n key 从空格分隔格式（如 `Export All (ZIP)`）统一为 dot 格式（如 `export.all.zip`），提升可维护性和一致性
- **ZIP 导入权限上下文修复**：ZIP 全量导入时线程池工作线程使用实际登录用户的 Authentication，而非系统默认的 anonymous 认证，修复导入时 `AccessDeniedException` 权限不足错误
- **审计日志用户名修复**：ZIP 全量导入的审计日志中用户名从 `anonymous` 改为实际页面登录用户
- **外部存储功能精简**：移除目录任务（Folder）级别的外部存储功能，仅保留系统凭据管理（Jenkins 根目录）下的外部存储功能，减少凭据扩散风险，降低攻击面
- **审计日志功能精简**：移除目录任务下的审计日志查看和配置功能，仅保留系统凭据管理下的审计日志功能，审计日志条目按时间倒序排列
- **审计日志持久化**：审计日志写入线程改为非 daemon 线程，注册 JVM shutdown hook 确保关闭时不丢失日志
- **加密代码去重**：将 `CredentialBackupService` 和 `FileExternalStorage` 中重复的 AES-256-GCM 加密/解密/PBKDF2 密钥派生代码提取到 `CryptoService` 统一管理
- **异常信息脱敏**：所有通用异常捕获不再向前端返回 `e.getMessage()`，改为返回通用错误提示，详细信息仅记录在服务端日志
- **审计日志弹窗布局优化**：最大保留天数配置和关闭按钮移到审计记录内容上方，提升用户体验
- **导入结果弹窗增强**：全量 ZIP 导入结果弹窗中每条凭据显示所在目录任务路径，便于定位凭据位置

### Fixed

- **批量导入全部失败**：修复 ZIP 全量导入时所有凭据导入结果均为失败的问题，根本原因是线程池中权限上下文丢失
- **Certificate 凭据导出类型错误**：修复 `getKeyStore()` 返回 `KeyStore` 而非 `SecretBytes` 的类型转换错误，改为通过 `getKeyStoreSource()` 获取原始字节
- **Certificate 凭据构造器参数顺序错误**：修复 `CertificateCredentialsImpl` 构造器中 `password` 与 `keyStoreSource` 参数位置颠倒的问题
- **导出时 ID HTML 转义问题**：修复导出凭据时对 `id`、`username` 等关键字段进行 HTML 转义导致导入时 ID 不匹配的问题
- **单元测试更新**：更新 `CredentialBackupServiceTest` 使用公开 API（`encryptData`/`decryptData`），更新 `FileExternalStorageTest` 适配 `.enc` 加密文件格式和新的目录结构

### Security

- **权限模型增强**：解密、导出、同步等敏感操作升级为 `Jenkins.ADMINISTER` 权限，防止低权限用户获取明文凭据
- **Zip Slip 漏洞修复**：对 ZIP 条目路径进行规范化检查，拒绝包含 `..` 或绝对路径的恶意条目
- **密码安全管理**：外部存储密码从 `String` 改为 `char[]`，使用后及时用 `Arrays.fill()` 擦除，防止 Heap Dump 泄露
- **加密密钥与 Jenkins master.key 绑定**：PBKDF2 密钥派生混入 Jenkins master.key，防止导出文件被离线暴力破解
- **JSON Schema 验证**：新增凭据类型白名单、字段白名单和长度校验，防止反序列化攻击和数据污染
- **审计日志脱敏**：credentialId 和 folder 使用 SHA-256 哈希摘要记录，避免泄露内部系统命名
- **导入限流**：ZIP 文件大小限制 20MB，单次导入凭据数量限制 1000 条
- **线程池生命周期管理**：使用 `@Terminator` 在 Jenkins 关闭时优雅关闭所有线程池，防止 ClassLoader 泄露

## [0.9.0] - 2025-05-25

### Added

- **目录任务凭据分层存储**：Jenkins 根目录下额外加密存储支持按目录层级保存凭据，以目录任务的 `fullName` 路径作为子目录结构，保持与 Jenkins 目录任务层级一致
- **全量 ZIP 导入导出**：Jenkins 首页「系统凭证管理」支持导入导出所有目录任务的凭据并打包为 ZIP 包
  - ZIP 包结构与 Jenkins 目录任务路径保持一致
  - 导出时使用 AES-256-GCM 加密保护
  - 导入时自动按层级结构恢复到对应目录任务
  - 支持覆盖现有凭据选项

### Fixed

- **文件夹凭据列表泄露系统级凭据**：修复目录任务下的凭证列表除了显示当前目录任务的凭据外，还错误地显示了 Jenkins 系统级凭据的问题。`CredentialsProvider.lookupCredentials()` 会递归返回父级凭据，现改为直接从文件夹自身的 `CredentialsStore` 获取凭据，确保只显示当前文件夹存储的凭据。影响范围：凭据列表、凭据查找、凭据导出、外部存储同步

## [0.8.0] - 2025-01-01

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
