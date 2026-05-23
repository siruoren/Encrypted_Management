package com.siruoren.encrypted_management.validator;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Localized messages for variable name validation.
 */
public class Messages {

    public static String VariableNameValidator_nameRequired() {
        return "Variable name is required";
    }

    public static String VariableNameValidator_nameTooLong() {
        return "Variable name must not exceed 255 characters";
    }

    public static String VariableNameValidator_nameInvalid() {
        return "Variable name must start with a letter or underscore, and contain only letters, digits, underscores, and hyphens";
    }

    public static String VariableNameValidator_nameReserved(@NonNull String name) {
        return "'" + name + "' is a reserved Jenkins variable name";
    }
}
