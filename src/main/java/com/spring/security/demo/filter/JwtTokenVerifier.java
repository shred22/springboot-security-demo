package com.spring.security.demo.filter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.lang.Strings;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtTokenVerifier extends OncePerRequestFilter {

  /**
   * will be invoked Once for every incoming request
   *
   * @param request
   * @param response
   * @param filterChain
   * @throws ServletException
   * @throws IOException
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    String authorizationHeader = request.getHeader("Authorization");
    if (StringUtils.isEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer")) {
      filterChain.doFilter(request, response);
    }
    authorizationHeader = authorizationHeader.replace("Bearer ", "");
    try {
      Jws<Claims> claimsJws = Jwts.parser()
          .setSigningKey(Files.readString(
              Path.of(new URI("file:///" + new ClassPathResource("keys/private-key.pem").getFile()
                  .getAbsolutePath())), Charset
                  .defaultCharset())).parseClaimsJws(authorizationHeader);

      String username = claimsJws.getBody().getSubject();
      List<Map<String, String>> authorities = (List<Map<String, String>>) claimsJws.getBody().get("authorities");
      Set<SimpleGrantedAuthority> grantedAuthorities = authorities.stream()
          .map(m -> new SimpleGrantedAuthority(m.get("authority")))
          .collect(Collectors.toSet());

      Authentication authentication
          = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);

      SecurityContextHolder.getContext().setAuthentication(authentication);
      filterChain.doFilter(request, response);

    } catch (JwtException | URISyntaxException e) {
      throw new RuntimeException(String.format("Token %s Can't be Trusted", authorizationHeader));
    }
  }
}
