package com.siruoren.encrypted_management.service;

import java.util.concurrent.*;

/**
 * Thread pool service for non-blocking async operations.
 * Used for save, update, delete operations that should not block the UI.
 */
public class AsyncTaskService {

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
                private int count = 0;
                @Override
                public Thread newThread(Runnable r) {
                    Thread t = new Thread(r, "EncryptedManagement-Worker-" + (count++));
                    t.setDaemon(true);
                    return t;
                }
            },
            new ThreadPoolExecutor.CallerRunsPolicy()
        );
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
     */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
