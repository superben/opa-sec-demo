package com.example.opasecdemo.model;

public class Http {
    String method;
    String path;
    Header Headers;

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public Header getHeaders() {
        return Headers;
    }

    public void setHeaders(Header headers) {
        Headers = headers;
    }

    public Http(String method, String path, Header Headers) {
        this.method = method;
        this.path = path;
        this.Headers = Headers;
    }

}
