package com.security.demo.backend.model;

import lombok.Data;

@Data
public class AwsKmsResult {
    private String publicKey;
    private String type;
    private String aliasName;
}
