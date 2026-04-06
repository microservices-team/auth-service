package com.diegoanyosa.authservice.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class UserInfoResponse {
    private String userId;
    private String email;
    private String roles;
}
