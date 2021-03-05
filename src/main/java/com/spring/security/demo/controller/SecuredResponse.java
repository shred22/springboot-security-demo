package com.spring.security.demo.controller;

import java.util.Collection;
import java.util.List;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;


@Getter
@Setter
@Builder
public class SecuredResponse {

  private String username;
  private Object encodedPassword;
  private Collection<? extends GrantedAuthority> grantedAuthorities;
  private List<String> roles;

}
