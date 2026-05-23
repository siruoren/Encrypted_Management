package com.siruoren.encrypted_management;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.EnvVars;
import hudson.Extension;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.EnvironmentContributor;
import com.siruoren.encrypted_management.model.ModelEntry;
import com.siruoren.encrypted_management.service.EncryptedVariableService;
import jenkins.model.Jenkins;

import edu.umd.cs.findbugs.annotations.NonNull;

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Contributes encrypted variables as environment variables to builds.
 * Variables from the current folder (and parent folders) are injected
 * so that all tasks under the folder can use them like native Jenkins variables.
 *
 * Usage in pipelines:
 *   echo env.MY_SECRET
 *   echo "${MY_SECRET}"
 */
@Extension
public class EncryptedEnvironmentContributor extends EnvironmentContributor {

    private static final Logger LOGGER = Logger.getLogger(EncryptedEnvironmentContributor.class.getName());

    @Override
    public void buildEnvironmentFor(@NonNull Run run, @NonNull EnvVars envs, @NonNull TaskListener listener) throws IOException {
        // Find the parent folder of the job
        Item parent = run.getParent(); // the Job
        ItemGroup itemGroup = parent.getParent();

        // Collect entries from all ancestor folders
        collectAndInjectVariables(itemGroup, envs, listener);
    }

    /**
     * Recursively collect encrypted variables from the folder hierarchy.
     * Parent folder variables are injected first, child folder variables can override.
     */
    private void collectAndInjectVariables(ItemGroup itemGroup, @NonNull EnvVars envs, @NonNull TaskListener listener) {
        if (itemGroup instanceof Folder) {
            Folder folder = (Folder) itemGroup;

            // First, process parent folders (so child overrides parent)
            collectAndInjectVariables(folder.getParent(), envs, listener);

            // Then inject this folder's variables
            List<ModelEntry> entries = EncryptedVariableService.getInstance().getEntries(folder.getFullName());
            for (ModelEntry entry : entries) {
                String varName = entry.getName();
                String decryptedValue = entry.getDecryptedValue();

                if (decryptedValue != null) {
                    envs.put(varName, decryptedValue);

                    // For USERNAME_PASSWORD type, also inject _USERNAME suffix variable
                    if (entry.getType() == ModelEntry.EntryType.USERNAME_PASSWORD && entry.getUsername() != null) {
                        envs.put(varName + "_USERNAME", entry.getUsername());
                    }

                    // For SSH_KEY_PAIR type, also inject _PUBLIC_KEY suffix variable
                    if (entry.getType() == ModelEntry.EntryType.SSH_KEY_PAIR && entry.getSshPublicKey() != null) {
                        envs.put(varName + "_PUBLIC_KEY", entry.getSshPublicKey());
                    }

                    LOGGER.log(Level.FINE, "Injected encrypted variable: {0} from folder: {1}",
                        new Object[]{varName, folder.getFullName()});
                }
            }
        } else if (itemGroup instanceof Jenkins) {
            // Reached root level, no more folders to process
            return;
        }
    }
}
