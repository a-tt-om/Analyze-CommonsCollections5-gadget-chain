package com.java.insecure_deserialization.model;

import java.io.Serializable;

public class User implements Serializable {
    final private String username;
    final private String password;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
