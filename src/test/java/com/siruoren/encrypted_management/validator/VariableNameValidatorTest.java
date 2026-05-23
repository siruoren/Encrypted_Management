package com.siruoren.encrypted_management.validator;

import org.junit.Test;
import static org.junit.Assert.*;

public class VariableNameValidatorTest {

    @Test
    public void testValidNames() {
        assertTrue(VariableNameValidator.validate("MY_SECRET").isValid());
        assertTrue(VariableNameValidator.validate("my_secret").isValid());
        assertTrue(VariableNameValidator.validate("_private").isValid());
        assertTrue(VariableNameValidator.validate("API_KEY_2024").isValid());
        assertTrue(VariableNameValidator.validate("db-password").isValid());
        assertTrue(VariableNameValidator.validate("a").isValid());
        assertTrue(VariableNameValidator.validate("_").isValid());
    }

    @Test
    public void testInvalidNames() {
        // Starts with digit
        assertFalse(VariableNameValidator.validate("1secret").isValid());
        // Contains spaces
        assertFalse(VariableNameValidator.validate("my secret").isValid());
        // Contains special characters
        assertFalse(VariableNameValidator.validate("secret!@#").isValid());
        // Starts with hyphen
        assertFalse(VariableNameValidator.validate("-secret").isValid());
        // Empty
        assertFalse(VariableNameValidator.validate("").isValid());
        // Null
        assertFalse(VariableNameValidator.validate(null).isValid());
    }

    @Test
    public void testReservedNames() {
        assertFalse(VariableNameValidator.validate("BUILD_NUMBER").isValid());
        assertFalse(VariableNameValidator.validate("JENKINS_URL").isValid());
        assertFalse(VariableNameValidator.validate("WORKSPACE").isValid());
        assertFalse(VariableNameValidator.validate("HOME").isValid());
    }

    @Test
    public void testNameTooLong() {
        StringBuilder sb = new StringBuilder();
        sb.append("a".repeat(256));
        assertFalse(VariableNameValidator.validate(sb.toString()).isValid());
    }

    @Test
    public void testMaxLengthValid() {
        StringBuilder sb = new StringBuilder();
        sb.append("a".repeat(255));
        assertTrue(VariableNameValidator.validate(sb.toString()).isValid());
    }
}
