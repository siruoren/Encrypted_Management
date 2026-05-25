# Changelog

All notable changes to the Encrypted Management plugin will be documented in this file.

## [1.0.0] - 2025-05-24

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
  - 支持 AES-256-GCM 加密存储，页面设置加密密码
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
  - 文件存储：per-credential 细粒度 ReentrantLock，避免全局锁阻塞
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
