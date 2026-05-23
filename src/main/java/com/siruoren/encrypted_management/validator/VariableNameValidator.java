package com.siruoren.encrypted_management.validator;

import java.util.regex.Pattern;

/**
 * Validates encrypted variable names for compliance.
 * Rules:
 * - Must start with a letter or underscore
 * - Can only contain letters, digits, underscores, and hyphens
 * - Must be between 1 and 255 characters
 * - Must not be a reserved Jenkins name
 */
public class VariableNameValidator {

    private static final Pattern VALID_NAME_PATTERN = Pattern.compile("^[a-zA-Z_][a-zA-Z0-9_-]{0,254}$");

    private static final String[] RESERVED_NAMES = {
        "BUILD_NUMBER", "BUILD_ID", "BUILD_TAG", "BUILD_URL",
        "EXECUTOR_NUMBER", "HOME", "JENKINS_URL", "JOB_NAME",
        "JOB_URL", "NODE_LABELS", "NODE_NAME", "WORKSPACE",
        "BRANCH_NAME", "CHANGE_ID", "CHANGE_URL", "CHANGE_TITLE",
        "CHANGE_AUTHOR", "CHANGE_AUTHOR_DISPLAY_NAME", "CHANGE_TARGET",
        "CHANGE_BRANCH", "CHANGE_FORK", "RUN_DISPLAY_URL",
        "RUN_CHANGES_DISPLAY_URL", "JENKINS_HOME", "HUDSON_HOME"
    };

    public static ValidationResult validate(String name) {
        if (name == null || name.trim().isEmpty()) {
            return ValidationResult.error(Messages.VariableNameValidator_nameRequired());
        }

        String trimmed = name.trim();

        if (trimmed.length() > 255) {
            return ValidationResult.error(Messages.VariableNameValidator_nameTooLong());
        }

        if (!VALID_NAME_PATTERN.matcher(trimmed).matches()) {
            return ValidationResult.error(Messages.VariableNameValidator_nameInvalid());
        }

        for (String reserved : RESERVED_NAMES) {
            if (reserved.equalsIgnoreCase(trimmed)) {
                return ValidationResult.error(Messages.VariableNameValidator_nameReserved(trimmed));
            }
        }

        return ValidationResult.ok();
    }

    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;

        private ValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult ok() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult error(String message) {
            return new ValidationResult(false, message);
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }
}
