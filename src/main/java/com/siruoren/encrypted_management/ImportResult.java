package com.siruoren.encrypted_management;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 导入结果模型，封装每条凭据的导入状态
 * 支持线程安全的计数器，适用于并发导入场景
 */
public class ImportResult {

    /** 单条凭据导入状态 */
    public enum Status {
        IMPORTED,   // 新增成功
        UPDATED,    // 覆盖更新
        SKIPPED,    // 跳过（已存在且未覆盖）
        FAILED      // 失败
    }

    /** 单条凭据导入结果 */
    public static class ItemResult {
        private final String id;
        private final String description;
        private final String type;
        private final Status status;
        private final String message;

        public ItemResult(String id, String description, String type, Status status, String message) {
            this.id = id;
            this.description = description;
            this.type = type;
            this.status = status;
            this.message = message;
        }

        public String getId() { return id; }
        public String getDescription() { return description; }
        public String getType() { return type; }
        public Status getStatus() { return status; }
        public String getMessage() { return message; }

        public JSONObject toJson() {
            JSONObject obj = new JSONObject();
            obj.put("id", id != null ? id : "");
            obj.put("description", description != null ? description : "");
            obj.put("type", type != null ? type : "");
            obj.put("status", status.name());
            obj.put("message", message != null ? message : "");
            return obj;
        }
    }

    private final AtomicInteger imported = new AtomicInteger(0);
    private final AtomicInteger updated = new AtomicInteger(0);
    private final AtomicInteger skipped = new AtomicInteger(0);
    private final AtomicInteger failed = new AtomicInteger(0);
    private final List<ItemResult> items = java.util.Collections.synchronizedList(new ArrayList<ItemResult>());
    private final String folderName;

    public ImportResult(String folderName) {
        this.folderName = folderName;
    }

    /** 线程安全：记录一条凭据导入结果 */
    public void record(Status status, String id, String description, String type, String message) {
        switch (status) {
            case IMPORTED: imported.incrementAndGet(); break;
            case UPDATED:  updated.incrementAndGet(); break;
            case SKIPPED:  skipped.incrementAndGet(); break;
            case FAILED:   failed.incrementAndGet(); break;
        }
        items.add(new ItemResult(id, description, type, status, message));
    }

    public void record(Status status, String id, String description, String type) {
        record(status, id, description, type, null);
    }

    /** 合并另一个ImportResult到当前结果 */
    public void merge(ImportResult other) {
        imported.addAndGet(other.imported.get());
        updated.addAndGet(other.updated.get());
        skipped.addAndGet(other.skipped.get());
        failed.addAndGet(other.failed.get());
        items.addAll(other.items);
    }

    public int getImported() { return imported.get(); }
    public int getUpdated() { return updated.get(); }
    public int getSkipped() { return skipped.get(); }
    public int getFailed() { return failed.get(); }
    public int getTotal() { return imported.get() + updated.get() + skipped.get() + failed.get(); }
    public String getFolderName() { return folderName; }
    public List<ItemResult> getItems() { return items; }

    /** 转为JSON，供API返回 */
    public JSONObject toJson() {
        JSONObject obj = new JSONObject();
        obj.put("folderName", folderName);
        obj.put("imported", imported.get());
        obj.put("updated", updated.get());
        obj.put("skipped", skipped.get());
        obj.put("failed", failed.get());
        obj.put("total", getTotal());

        JSONArray itemsArr = new JSONArray();
        for (ItemResult item : items) {
            itemsArr.add(item.toJson());
        }
        obj.put("items", itemsArr);
        return obj;
    }

    /** 生成汇总消息 */
    public String getSummaryMessage() {
        return String.format("导入完成: 新增 %d, 覆盖 %d, 跳过 %d, 失败 %d",
                imported.get(), updated.get(), skipped.get(), failed.get());
    }
}
