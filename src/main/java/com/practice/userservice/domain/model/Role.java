package com.practice.userservice.domain.model;

public enum Role {
    ROLE_USER("ROLE_USER"),
    ROLE_ADMIN("ROLE_ADMIN"),
    ROLE_MANAGER("ROLE_MANAGER"),
    ROLE_SUPER_ADMIN("ROLE_SUPER_ADMIN");

    public final String stringValue;

    private Role(String label) {
        this.stringValue = label;
    }
}

