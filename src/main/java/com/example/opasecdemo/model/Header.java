package com.example.opasecdemo.model;

public class Header {
    String authorization;

    public String getAuthorization() {
        return authorization;
    }

    public void setAuthorization(String authorization) {
        this.authorization = authorization;
    }

    public Header(String authorization) {
        this.authorization = authorization;
    }
}
