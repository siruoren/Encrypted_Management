package com.siruoren.encrypted_management;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.security.AnyTypePermission;
import com.thoughtworks.xstream.security.ExplicitTypePermission;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import com.siruoren.encrypted_management.model.ModelEntry;
import com.siruoren.encrypted_management.service.EncryptedVariableService;
import jenkins.model.Jenkins;

import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Plugin initialization class.
 * Handles startup lifecycle and XStream configuration.
 */
@Extension
public class EncryptedManagementPlugin {

    private static final Logger LOGGER = Logger.getLogger(EncryptedManagementPlugin.class.getName());

    @Initializer(after = InitMilestone.PLUGINS_STARTED)
    public static void init() {
        LOGGER.log(Level.INFO, "Encrypted Management Plugin initialized");
        configureXStream();
        // Pre-load cache for all folders
        EncryptedVariableService.getInstance().reload();
    }

    /**
     * Configure XStream to allow serialization/deserialization of our model classes.
     * Required for Jenkins 2.x+ which has XStream security restrictions.
     */
    private static void configureXStream() {
        try {
            XStream xstream = Jenkins.XSTREAM;

            // Register type permissions for our model classes
            xstream.addPermission(new ExplicitTypePermission(new String[]{
                ModelEntry.class.getName(),
                ModelEntry.EntryType.class.getName()
            }));

            // Add alias for cleaner XML output
            xstream.alias("modelEntry", ModelEntry.class);
            xstream.alias("entryType", ModelEntry.EntryType.class);

            LOGGER.log(Level.INFO, "XStream configured for Encrypted Management Plugin");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to configure XStream for Encrypted Management Plugin", e);
        }
    }
}
