package com.siruoren.encrypted_management;

import hudson.Util;
import jenkins.model.Jenkins;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 独立审计日志系统
 * 与Jenkins自身审计日志分离，记录所有凭据操作
 * 日志存储在JENKINS_HOME/encrypted-management-audit/目录下
 *
 * 并发优化：
 * - 使用单线程Executor顺序写入日志，避免多线程文件写入冲突
 * - volatile保证maxLogFiles的可见性
 * - 读取时使用快照，不阻塞写入
 */
public class AuditLogger {
    private static final Logger LOGGER = Logger.getLogger(AuditLogger.class.getName());
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final long MAX_LOG_SIZE_BYTES = 50 * 1024 * 1024; // 50MB per file

    private static volatile int maxLogFiles = 30; // 保留30天日志（可配置）

    // 单线程日志写入器，保证顺序写入、防阻塞、防并发冲突
    private static final ExecutorService logWriter = Executors.newSingleThreadExecutor(new ThreadFactory() {
        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "EncryptedManagement-AuditLogger");
            t.setDaemon(true); // 守护线程，JVM关闭时自动退出
            return t;
        }
    });

    private AuditLogger() {}

    /**
     * 获取最大日志保留天数
     */
    public static int getMaxLogFiles() {
        return maxLogFiles;
    }

    /**
     * 设置最大日志保留天数
     */
    public static void setMaxLogFiles(int max) {
        if (max > 0) {
            maxLogFiles = max;
        }
    }

    /**
     * 获取审计日志目录
     */
    private static File getAuditDir() {
        File dir = new File(Jenkins.get().getRootDir(), "encrypted-management-audit");
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    /**
     * 获取当天的日志文件
     */
    private static File getLogFile() {
        String dateStr = LocalDateTime.now().format(DATE_FORMAT);
        return new File(getAuditDir(), "audit-" + dateStr + ".log");
    }

    /**
     * 记录审计日志（异步非阻塞）
     * 使用单线程Executor顺序写入，避免并发冲突和阻塞调用线程
     *
     * 安全措施：
     * - credentialId 使用哈希摘要，避免直接记录原始ID泄露内部命名
     * - folder 使用哈希摘要，避免泄露Git仓库、生产环境等命名
     * - 绝对禁止记录任何凭据的明文值
     */
    public static void log(String folderName, String action, String credentialId, String credentialType, String detail) {
        String user = getCurrentUser();
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        // 脱敏：对credentialId和folder进行哈希处理
        String safeCredId = credentialId != null ? hashForAudit(credentialId) : "*";
        String safeFolder = folderName != null ? hashForAudit(folderName) : "*";
        String logLine = String.format("[%s] user=%s folder=%s action=%s credentialId=%s type=%s detail=%s",
                timestamp, user, safeFolder, action, safeCredId, credentialType, detail != null ? detail : "");

        // 异步写入文件，不阻塞调用线程
        logWriter.submit(new LogWriteTask(logLine));

        // 同时输出到Jenkins日志
        LOGGER.info(logLine);
    }

    /**
     * 日志写入任务
     */
    private static class LogWriteTask implements Runnable {
        private final String logLine;

        LogWriteTask(String logLine) {
            this.logLine = logLine;
        }

        @Override
        public void run() {
            try {
                File logFile = getLogFile();
                // 检查文件大小，超过限制则停止写入（防止磁盘满）
                if (logFile.exists() && logFile.length() > MAX_LOG_SIZE_BYTES) {
                    LOGGER.warning("Audit log file exceeds size limit: " + logFile.getAbsolutePath());
                    return;
                }
                try (PrintWriter writer = new PrintWriter(new FileWriter(logFile, true))) {
                    writer.println(logLine);
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to write audit log", e);
            }
        }
    }

    /**
     * 记录简单操作日志
     */
    public static void logCreate(String folderName, String credentialId, String credentialType) {
        log(folderName, "CREATE", credentialId, credentialType, null);
    }

    public static void logRead(String folderName, String credentialId, String credentialType) {
        log(folderName, "READ", credentialId, credentialType, null);
    }

    public static void logUpdate(String folderName, String credentialId, String credentialType) {
        log(folderName, "UPDATE", credentialId, credentialType, null);
    }

    public static void logDelete(String folderName, String credentialId, String credentialType) {
        log(folderName, "DELETE", credentialId, credentialType, null);
    }

    public static void logExport(String folderName, String detail) {
        log(folderName, "EXPORT", "*", "*", detail);
    }

    public static void logImport(String folderName, String detail) {
        log(folderName, "IMPORT", "*", "*", detail);
    }

    public static void logGenerateKeyPair(String folderName) {
        log(folderName, "GENERATE_KEY_PAIR", "*", "SSH_KEY", null);
    }

    /**
     * 获取当前用户名
     */
    private static String getCurrentUser() {
        try {
            return Jenkins.get().getAuthentication().getName();
        } catch (Exception e) {
            return "anonymous";
        }
    }

    /**
     * 审计日志脱敏哈希：对敏感标识符进行SHA-256摘要
     * 返回前8位十六进制，足以区分不同对象但无法逆推原始值
     */
    private static String hashForAudit(String input) {
        if (input == null || input.isEmpty()) return "*";
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 4 && i < hash.length; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            // SHA-256 必定可用，此处仅为编译器要求
            return "****";
        }
    }

    /**
     * 读取审计日志（最近N条）
     * 读取文件快照，不阻塞写入线程
     */
    public static List<String> readRecentLogs(int limit) {
        File auditDir = getAuditDir();
        if (!auditDir.exists()) {
            return Collections.emptyList();
        }

        List<String> allLines = new ArrayList<>();
        File[] logFiles = auditDir.listFiles((dir, name) -> name.startsWith("audit-") && name.endsWith(".log"));

        if (logFiles == null || logFiles.length == 0) {
            return Collections.emptyList();
        }

        // 按文件名倒序排列（最新的在前）
        List<File> sortedFiles = new ArrayList<>();
        Collections.addAll(sortedFiles, logFiles);
        sortedFiles.sort((a, b) -> b.getName().compareTo(a.getName()));

        for (File f : sortedFiles) {
            try {
                List<String> lines = Files.readAllLines(f.toPath(), StandardCharsets.UTF_8);
                allLines.addAll(lines);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to read audit log file: " + f.getAbsolutePath(), e);
            }
            if (allLines.size() >= limit * 2) break; // 多读一些，后面截断
        }

        // 倒序（最新的在前），取limit条
        Collections.reverse(allLines);
        if (allLines.size() > limit) {
            allLines = allLines.subList(0, limit);
        }

        return allLines;
    }

    /**
     * 清理过期日志文件
     */
    public static int cleanOldLogs() {
        File auditDir = getAuditDir();
        if (!auditDir.exists()) {
            return 0;
        }

        int currentMaxFiles = maxLogFiles; // 快照读取，避免并发修改
        File[] logFiles = auditDir.listFiles((dir, name) -> name.startsWith("audit-") && name.endsWith(".log"));
        if (logFiles == null || logFiles.length <= currentMaxFiles) {
            return 0;
        }

        List<File> sortedFiles = new ArrayList<>();
        Collections.addAll(sortedFiles, logFiles);
        sortedFiles.sort((a, b) -> b.getName().compareTo(a.getName())); // 最新的在前

        int deleted = 0;
        for (int i = currentMaxFiles; i < sortedFiles.size(); i++) {
            if (sortedFiles.get(i).delete()) {
                deleted++;
            }
        }
        return deleted;
    }

    /**
     * 优雅关闭审计日志线程池（由ThreadPoolManager.shutdown()调用）
     */
    public static void shutdown() {
        if (logWriter != null && !logWriter.isShutdown()) {
            logWriter.shutdown();
            try {
                logWriter.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS);
                LOGGER.info("Audit logger thread pool shut down complete");
            } catch (InterruptedException e) {
                logWriter.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}
