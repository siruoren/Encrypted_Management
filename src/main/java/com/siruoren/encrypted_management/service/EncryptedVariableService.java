package com.siruoren.encrypted_management.service;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.XmlFile;
import hudson.model.Item;
import com.siruoren.encrypted_management.model.ModelEntry;
import jenkins.model.Jenkins;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Service for managing encrypted variable entries.
 * Stores entries per folder in XML files under the folder's directory.
 * Uses in-memory cache with ConcurrentHashMap for thread-safe access.
 */
public class EncryptedVariableService {

    private static final Logger LOGGER = Logger.getLogger(EncryptedVariableService.class.getName());
    private static final String ENTRIES_FILE_NAME = "encrypted-variables.xml";
    private static final EncryptedVariableService INSTANCE = new EncryptedVariableService();

    // Cache: folderFullName -> (variableName -> ModelEntry)
    private final ConcurrentHashMap<String, ConcurrentHashMap<String, ModelEntry>> cache = new ConcurrentHashMap<>();

    private EncryptedVariableService() {}

    public static EncryptedVariableService getInstance() {
        return INSTANCE;
    }

    /**
     * Get all entries for a folder.
     */
    @NonNull
    public List<ModelEntry> getEntries(@NonNull String folderFullName) {
        ConcurrentHashMap<String, ModelEntry> folderEntries = cache.computeIfAbsent(
            folderFullName, this::loadFromDisk
        );
        return new ArrayList<>(folderEntries.values());
    }

    /**
     * Get a specific entry by name from a folder.
     */
    public ModelEntry getEntry(@NonNull String folderFullName, @NonNull String name) {
        ConcurrentHashMap<String, ModelEntry> folderEntries = cache.computeIfAbsent(
            folderFullName, this::loadFromDisk
        );
        return folderEntries.get(name);
    }

    /**
     * Add or update an entry. Returns true if successful.
     */
    public synchronized boolean saveEntry(@NonNull ModelEntry entry) throws IOException {
        String folderFullName = entry.getFolderFullName();
        if (folderFullName == null || folderFullName.isEmpty()) {
            throw new IllegalArgumentException("Folder full name is required");
        }

        ConcurrentHashMap<String, ModelEntry> folderEntries = cache.computeIfAbsent(
            folderFullName, this::loadFromDisk
        );

        boolean isUpdate = folderEntries.containsKey(entry.getName());
        entry.setUpdatedTimestamp(System.currentTimeMillis());

        folderEntries.put(entry.getName(), entry);
        saveToDisk(folderFullName, folderEntries);

        LOGGER.log(Level.INFO, "{0} encrypted variable ''{1}'' in folder ''{2}''",
            new Object[]{isUpdate ? "Updated" : "Created", entry.getName(), folderFullName});

        return true;
    }

    /**
     * Delete an entry by name from a folder.
     */
    public synchronized boolean deleteEntry(@NonNull String folderFullName, @NonNull String name) throws IOException {
        ConcurrentHashMap<String, ModelEntry> folderEntries = cache.get(folderFullName);
        if (folderEntries == null) {
            return false;
        }

        ModelEntry removed = folderEntries.remove(name);
        if (removed != null) {
            saveToDisk(folderFullName, folderEntries);
            LOGGER.log(Level.INFO, "Deleted encrypted variable ''{0}'' from folder ''{1}''",
                new Object[]{name, folderFullName});
            return true;
        }
        return false;
    }

    /**
     * Check if an entry with the given name already exists in the folder.
     */
    public boolean entryExists(@NonNull String folderFullName, @NonNull String name) {
        ConcurrentHashMap<String, ModelEntry> folderEntries = cache.get(folderFullName);
        return folderEntries != null && folderEntries.containsKey(name);
    }

    /**
     * Invalidate cache for a folder (force reload on next access).
     */
    public void invalidateCache(@NonNull String folderFullName) {
        cache.remove(folderFullName);
    }

    /**
     * Get the XML file for storing entries of a folder.
     */
    private File getStorageFile(@NonNull String folderFullName) {
        Jenkins jenkins = Jenkins.get();
        Folder folder = getFolderByFullName(folderFullName);
        if (folder != null) {
            return new File(folder.getRootDir(), ENTRIES_FILE_NAME);
        }
        // Fallback: use Jenkins root with encoded path
        String safeName = folderFullName.replace('/', '_').replace('\\', '_');
        return new File(jenkins.getRootDir(), "encrypted-variables" + File.separator + safeName + ".xml");
    }

    private Folder getFolderByFullName(@NonNull String folderFullName) {
        Jenkins jenkins = Jenkins.get();
        Item item = jenkins.getItemByFullName(folderFullName);
        if (item instanceof Folder) {
            return (Folder) item;
        }
        return null;
    }

    @SuppressFBWarnings(value = "NP_NULL_ON_SOME_PATH", justification = "loadFromDisk handles null safely")
    private ConcurrentHashMap<String, ModelEntry> loadFromDisk(@NonNull String folderFullName) {
        ConcurrentHashMap<String, ModelEntry> entries = new ConcurrentHashMap<>();
        File file = getStorageFile(folderFullName);
        if (!file.exists()) {
            return entries;
        }

        try {
            XmlFile xmlFile = new XmlFile(Jenkins.XSTREAM, file);
            List<ModelEntry> list = new ArrayList<>();
            xmlFile.unmarshal(list);
            for (ModelEntry entry : list) {
                if (entry.getName() != null) {
                    entries.put(entry.getName(), entry);
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to load encrypted variables for folder: " + folderFullName, e);
        }
        return entries;
    }

    private void saveToDisk(@NonNull String folderFullName, @NonNull ConcurrentHashMap<String, ModelEntry> entries) throws IOException {
        File file = getStorageFile(folderFullName);
        file.getParentFile().mkdirs();

        List<ModelEntry> list = new ArrayList<>(entries.values());
        XmlFile xmlFile = new XmlFile(Jenkins.XSTREAM, file);
        xmlFile.write(list);
    }

    /**
     * Reload all data from disk.
     */
    public void reload() {
        cache.clear();
        LOGGER.log(Level.INFO, "Encrypted variable cache cleared");
    }
}
