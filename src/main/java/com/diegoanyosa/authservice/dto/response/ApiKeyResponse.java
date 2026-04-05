package com.diegoanyosa.authservice.dto.response;

import lombok.*;
import java.time.LocalDateTime;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class ApiKeyResponse {
    private String id;
    private String name;
    private String prefix;
    private String rawKey;       // Only present on creation, null on list
    private LocalDateTime createdAt;
}
