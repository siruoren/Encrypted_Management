package com.siruoren.encrypted_management.service;

import org.junit.Test;
import static org.junit.Assert.*;

public class AsyncTaskServiceTest {

    @Test
    public void testSubmitCallable() throws Exception {
        AsyncTaskService service = AsyncTaskService.getInstance();
        var future = service.submit(() -> "hello");
        assertEquals("hello", future.get());
    }

    @Test
    public void testSubmitRunnable() throws Exception {
        AsyncTaskService service = AsyncTaskService.getInstance();
        var future = service.submit(() -> {}, null);
        assertNull(future.get());
    }

    @Test
    public void testPoolStats() {
        AsyncTaskService service = AsyncTaskService.getInstance();
        String stats = service.getPoolStats();
        assertNotNull(stats);
        assertTrue(stats.contains("Active"));
        assertTrue(stats.contains("Pool"));
    }
}
