package com.example.demo.payload.response;

import java.time.Instant;

public record ErrorResponse(
        Instant timestamp,
        Integer status,
        String error
) {
}
