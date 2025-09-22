package com.example.demo.model;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Data
@Document(collection = "reset_tokens")
public class PasswordResetToken {
    @Id
    private String id;

    private String token;
    private String userId;
    private Instant expiryDate;

    private long expirationSeconds;

    public PasswordResetToken(String token, String userId, long expirationSeconds) {
        this.token = token;
        this.userId = userId;
        this.expirationSeconds = expirationSeconds;
        this.expiryDate = Instant.now().plusSeconds(expirationSeconds);
    }
}
