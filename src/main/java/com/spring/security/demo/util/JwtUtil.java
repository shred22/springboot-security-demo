package com.spring.security.demo.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

  @Value("${jwt.signing.private-key}")
  private String privateKeyPath;
  @Value("${jwt.verification.public-key}")
  private String publicKeyPath;

  public String extractUsername(String token) throws IOException, URISyntaxException {
    return extractClaim(token, Claims::getSubject);
  }

  public Date extractExpiration(String token) throws IOException, URISyntaxException {
    return extractClaim(token, Claims::getExpiration);
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver)
      throws IOException, URISyntaxException {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }
  private Claims extractAllClaims(String token) throws IOException, URISyntaxException {
    String key = Files.readString(Path.of(new URI(publicKeyPath)), Charset.defaultCharset());
    return Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
  }

  private Boolean isTokenExpired(String token) throws IOException, URISyntaxException {
    return extractExpiration(token).before(new Date());
  }

  public String generateToken(UserDetails userDetails) throws IOException, URISyntaxException {
    Map<String, Object> claims = new HashMap<>();
    return createToken(claims, userDetails.getUsername());
  }

  private String createToken(Map<String, Object> claims, String subject)
      throws IOException, URISyntaxException {



    return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
        .signWith(SignatureAlgorithm.HS256, Files.readString(Path.of(new URI("file:///"+new ClassPathResource("keys/private-key.pem").getFile().getAbsolutePath())), Charset.defaultCharset())).compact();
  }

  public Boolean validateToken(String token, UserDetails userDetails)
      throws IOException, URISyntaxException {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }
}
