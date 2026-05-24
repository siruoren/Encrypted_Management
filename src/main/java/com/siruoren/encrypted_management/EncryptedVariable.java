package com.siruoren.encrypted_management;

import hudson.util.Secret;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

/**
 * 加密变量数据模型，存储变量名和加密值
 */
public class EncryptedVariable implements Serializable {
    private static final long serialVersionUID = 1L;

    private final String name;
    private final Secret value;

    @DataBoundConstructor
    public EncryptedVariable(String name, Secret value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public Secret getValue() {
        return value;
    }

    public String getEncryptedValue() {
        return value != null ? value.getEncryptedValue() : "";
    }

    public String getPlainText() {
        return value != null ? Secret.toString(value) : "";
    }
}
