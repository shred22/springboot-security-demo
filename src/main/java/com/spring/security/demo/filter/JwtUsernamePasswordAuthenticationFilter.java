package com.spring.security.demo.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.security.demo.controller.AuthenticationRequest;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


  private final AuthenticationManager authenticationManager;

  public JwtUsernamePasswordAuthenticationFilter(
      AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response)
      throws AuthenticationException {
    AuthenticationRequest authenticationRequest = null;
    try {
      authenticationRequest = new ObjectMapper()
          .readValue(request.getInputStream(), AuthenticationRequest.class);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
            authenticationRequest.getPassword()));
  }

  /**
   * This will be called after attemptAuthentication() is Successful.
   *
   * @param request
   * @param response
   * @param chain
   * @param authResult
   * @throws IOException
   * @throws ServletException
   */
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    String token = null;
    try {
      token = Jwts.builder().setSubject(authResult.getName())
          .claim("authorities", authResult.getAuthorities())
          .setIssuedAt(new Date())
          .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
          .signWith(SignatureAlgorithm.HS256, Files.readString(
              Path.of(new URI("file:///" + new ClassPathResource("keys/private-key.pem").getFile()
                  .getAbsolutePath())), Charset
                  .defaultCharset())).compact();
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
    response.addHeader("Authorization", "Bearer " + token);
  }
}
