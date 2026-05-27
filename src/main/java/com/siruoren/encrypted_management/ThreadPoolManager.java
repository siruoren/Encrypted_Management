package com.siruoren.encrypted_management;

import hudson.Extension;
import hudson.init.Terminator;
import jenkins.model.Jenkins;

import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 线程池管理器，提供多线程并发控制，防止内存泄露
 * <p>
 * 使用 daemon 线程，JVM 退出时自动回收
 * 使用有界队列防止 OOM
 * 使用 @Terminator 在 Jenkins 关闭时优雅关闭线程池
 */
@Extension
public class ThreadPoolManager {
    private static final Logger LOGGER = Logger.getLogger(ThreadPoolManager.class.getName());

    private static final int CORE_POOL_SIZE = Math.max(2, Runtime.getRuntime().availableProcessors());
    private static final int MAX_POOL_SIZE = CORE_POOL_SIZE * 2;
    private static final int QUEUE_CAPACITY = 100;
    private static final long KEEP_ALIVE_SECONDS = 60L;

    private volatile ExecutorService executor;

    /**
     * 获取线程池实例，双重检查锁保证线程安全
     */
    public ExecutorService getExecutor() {
        if (executor == null || executor.isShutdown()) {
            synchronized (this) {
                if (executor == null || executor.isShutdown()) {
                    executor = createExecutor();
                    LOGGER.info("Thread pool created with core size: " + CORE_POOL_SIZE);
                }
            }
        }
        return executor;
    }

    /**
     * 创建有界线程池
     */
    private ExecutorService createExecutor() {
        ThreadPoolExecutor pool = new ThreadPoolExecutor(
                CORE_POOL_SIZE,
                MAX_POOL_SIZE,
                KEEP_ALIVE_SECONDS,
                TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                new EncryptedManagementThreadFactory(),
                new ThreadPoolExecutor.CallerRunsPolicy()
        );
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }

    /**
     * Jenkins 关闭时优雅关闭线程池
     */
    @Terminator
    public void shutdown() {
        if (executor != null && !executor.isShutdown()) {
            LOGGER.info("Shutting down thread pool...");
            executor.shutdown();
            try {
                if (!executor.awaitTermination(15, TimeUnit.SECONDS)) {
                    LOGGER.warning("Thread pool did not terminate in 15 seconds, forcing shutdown");
                    List<Runnable> dropped = executor.shutdownNow();
                    LOGGER.warning("Dropped " + dropped.size() + " pending tasks");
                    if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                        LOGGER.severe("Thread pool did not terminate after forced shutdown");
                    }
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            LOGGER.info("Thread pool shut down complete");
        }

        // 同时关闭审计日志线程池
        AuditLogger.shutdown();
    }

    /**
     * 获取单例实例
     */
    public static ThreadPoolManager getInstance() {
        Jenkins jenkins = Jenkins.get();
        if (jenkins == null) {
            throw new IllegalStateException("Jenkins instance is not available");
        }
        return jenkins.getExtensionList(ThreadPoolManager.class).get(0);
    }

    /**
     * 自定义线程工厂，创建 daemon 线程，防止内存泄露
     */
    private static class EncryptedManagementThreadFactory implements ThreadFactory {
        private final AtomicInteger threadNumber = new AtomicInteger(1);

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(r, "EncryptedManagement-Worker-" + threadNumber.getAndIncrement());
            t.setDaemon(true);
            t.setPriority(Thread.NORM_PRIORITY);
            // 设置未捕获异常处理器，防止线程静默死亡
            t.setUncaughtExceptionHandler((thread, throwable) ->
                    LOGGER.log(Level.SEVERE, "Uncaught exception in thread: " + thread.getName(), throwable)
            );
            return t;
        }
    }
}
