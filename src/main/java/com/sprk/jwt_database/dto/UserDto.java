package com.sprk.jwt_database.dto;

import lombok.Data;

@Data
public class UserDto {
    private String name;
    private String password;
    private String role;
}
