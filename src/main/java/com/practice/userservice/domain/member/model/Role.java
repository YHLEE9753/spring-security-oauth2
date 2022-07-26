package com.practice.userservice.domain.member.model;

public enum Role {
    ROLE_NOTHING("ROLE_NOTHING"),
    ROLE_USER("ROLE_USER"),
    ROLE_ADMIN("ROLE_ADMIN"),
    ROLE_MANAGER("ROLE_MANAGER");

    public final String stringValue;

    private Role(String label) {
        this.stringValue = label;
    }
}

