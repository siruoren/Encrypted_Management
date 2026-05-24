package com.siruoren.encrypted_management.service;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Thread pool service for non-blocking async operations.
 * Registers JVM shutdown hook for graceful shutdown to prevent memory leaks.
 */
public class AsyncTaskService {

    private static final Logger LOGGER = Logger.getLogger(AsyncTaskService.class.getName());
    private static final int CORE_POOL_SIZE = 4;
    private static final int MAX_POOL_SIZE = 16;
    private static final long KEEP_ALIVE_SECONDS = 60L;
    private static final int QUEUE_CAPACITY = 100;

    private static final AsyncTaskService INSTANCE = new AsyncTaskService();

    private final ThreadPoolExecutor executor;

    private AsyncTaskService() {
        this.executor = new ThreadPoolExecutor(
            CORE_POOL_SIZE,
            MAX_POOL_SIZE,
            KEEP_ALIVE_SECONDS,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(QUEUE_CAPACITY),
            new ThreadFactory() {
                private final AtomicInteger count = new AtomicInteger(0);
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "EncryptedManagement-Worker-" + count.incrementAndGet());
                    t.setDaemon(true);
                    return t;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy()
        );

        // Allow core threads to time out so idle threads are reclaimed
        this.executor.allowCoreThreadTimeOut(true);

        // Register shutdown hook for clean JVM exit
        try {
            Runtime.getRuntime().addShutdownHook(new Thread(this::shutdown, "EncryptedManagement-ShutdownHook"));
        } catch (IllegalStateException e) {
            // JVM is already shutting down, ignore
        }
    }

    public static AsyncTaskService getInstance() {
        return INSTANCE;
    }

    /**
     * Submit a task for async execution. Returns a Future for tracking completion.
     */
    public <T> Future<T> submit(Callable<T> task) {
        return executor.submit(task);
    }

    /**
     * Submit a Runnable for async execution.
     */
    public Future<?> submit(Runnable task) {
        return executor.submit(task);
    }

    /**
     * Submit a Runnable with a result for async execution.
     */
    public <T> Future<T> submit(Runnable task, T result) {
        return executor.submit(task, result);
    }

    /**
     * Get pool stats for monitoring.
     */
    public String getPoolStats() {
        return String.format(
            "Active: %d, Completed: %d, Queue: %d, Pool: %d/%d",
            executor.getActiveCount(),
            executor.getCompletedTaskCount(),
            executor.getQueue().size(),
            executor.getPoolSize(),
            executor.getMaximumPoolSize()
        );
    }

    /**
     * Shutdown the thread pool gracefully.
     * First stops accepting new tasks, then waits for running tasks to complete.
     * After timeout, forces shutdown.
     */
    public void shutdown() {
        LOGGER.log(Level.INFO, "Shutting down AsyncTaskService...");
        executor.shutdown(); // Stop accepting new tasks
        try {
            if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                LOGGER.log(Level.WARNING, "AsyncTaskService did not terminate in 30s, forcing shutdown...");
                executor.shutdownNow();
                if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                    LOGGER.log(Level.SEVERE, "AsyncTaskService did not terminate after forced shutdown");
                }
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        LOGGER.log(Level.INFO, "AsyncTaskService shutdown complete");
    }
}
