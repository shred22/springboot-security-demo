package com.spring.security.demo.controller;

import java.util.Collection;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecuredController {

    @GetMapping(value = "/secured", produces = "application/json")
    public ResponseEntity<SecuredResponse> greeter() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        String username = authentication.getName();
        Object principal = authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities =
            authentication.getAuthorities();
        return ResponseEntity.ok(SecuredResponse.builder().username(""+principal).encodedPassword(authentication.getCredentials())
            .grantedAuthorities(authorities).build());

    }

    @GetMapping(value = "/management", produces = "application/json")
    public ResponseEntity<SecuredResponse> adminGreeter() {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication authentication = context.getAuthentication();
        String username = authentication.getName();
        Object principal = authentication.getPrincipal();
        Collection<? extends GrantedAuthority> authorities =
            authentication.getAuthorities();
        return ResponseEntity.ok(SecuredResponse.builder().username(username+ " : "+ principal).encodedPassword(authentication.getCredentials())
            .grantedAuthorities(authorities).build());
    }
}
