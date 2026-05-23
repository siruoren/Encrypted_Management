package com.siruoren.encrypted_management;

import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import com.siruoren.encrypted_management.service.EncryptedVariableService;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Plugin initialization class.
 * Handles startup lifecycle.
 */
@Extension
public class EncryptedManagementPlugin {

    private static final Logger LOGGER = Logger.getLogger(EncryptedManagementPlugin.class.getName());

    @Initializer(after = InitMilestone.PLUGINS_STARTED)
    public static void init() {
        LOGGER.log(Level.INFO, "Encrypted Management Plugin initialized");
        // Pre-load cache for all folders
        EncryptedVariableService.getInstance().reload();
    }
}
