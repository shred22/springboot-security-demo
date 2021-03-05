package com.spring.security.demo.controller;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationRequest {
  private String username;
  private String password;
}
