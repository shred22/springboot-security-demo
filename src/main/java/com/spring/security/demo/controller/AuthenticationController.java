package com.spring.security.demo.controller;

import com.spring.security.demo.model.AuthenticationResponse;
import com.spring.security.demo.model.UserDetailsImpl;
import com.spring.security.demo.util.JwtUtil;

import java.io.IOException;
import java.net.URISyntaxException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

  private final JwtUtil jwtUtil;
  private final AuthenticationManager authenticationManager;
  private final UserDetailsService userDetailsService;

  public AuthenticationController(JwtUtil jwtUtil, AuthenticationManager authenticationManager,
      UserDetailsService userDetailsService) {
    this.jwtUtil = jwtUtil;
    this.authenticationManager = authenticationManager;
    this.userDetailsService = userDetailsService;
  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request)
      throws IOException, URISyntaxException {
    Authentication authentication = null;
    try {
      authentication = authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
    } catch (BadCredentialsException e) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
    }
    UserDetails userDetails = userDetailsService
        .loadUserByUsername(((UserDetailsImpl) authentication.getPrincipal()).getUsername());
    return ResponseEntity.ok(AuthenticationResponse.builder().jwt(jwtUtil.generateToken(userDetails)).build());
  }
}
