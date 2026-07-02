package com.ifms.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
    
    @JsonProperty("status")
    private String status;
    
    @JsonProperty("authToken")
    private String authToken;
    
    @JsonProperty("sek")
    private String sek;
}