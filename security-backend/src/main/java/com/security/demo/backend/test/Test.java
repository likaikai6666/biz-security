package com.security.demo.backend.test;

public class Test {
    public static void main(String[] args) {
        String backend = "X-App-Id=finance-app-001&X-Timestamp=1763440755384&X-Nonce=3MjGp80CBNKKqs58pXQdvCPeWQrhHzyX&X-Sign-Alg=RSA-PSS-SHA256&deviceId=device-lhr2j7tme&bodyDigest=MgfTGYdamPQ3szmZqvcS2A/KPxQca7XqZ+JUV6Vq6C0=";
        String frontend= "X-App-Id=finance-app-001&X-Timestamp=1763440750657&X-Nonce=HcYS2Wv9jf1ARfUOLG4d7KPF6ZrMQ6gH&X-Sign-Alg=RSA-PSS-SHA256&deviceId=device-lhr2j7tme&bodyDigest=azyJm4fZUBDXjb+2u9Kd9pPOMeetT25nOWWlqXfCCzA=";
        System.out.println(frontend.equals(backend));
    }
}
