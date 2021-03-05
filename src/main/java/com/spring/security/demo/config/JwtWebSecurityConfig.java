package com.spring.security.demo.config;

import com.spring.security.demo.filter.JwtTokenVerifier;
import com.spring.security.demo.filter.JwtUsernamePasswordAuthenticationFilter;
import com.spring.security.demo.provider.CustomAuthenticationProvider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Slf4j
@EnableWebSecurity
public class JwtWebSecurityConfig extends WebSecurityConfigurerAdapter {

  private final CustomAuthenticationProvider authenticationProvider;
  private final UserDetailsService userDetailsService;

  public JwtWebSecurityConfig(CustomAuthenticationProvider authenticationProvider, UserDetailsService userDetailsService) {
    this.authenticationProvider = authenticationProvider;
    this.userDetailsService = userDetailsService;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info("Using default configure(HttpSecurity). "
        + "If subclassed this will potentially override subclass configure(HttpSecurity).");
    http.csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(new JwtUsernamePasswordAuthenticationFilter(authenticationManagerBean()))
        .addFilterAfter(new JwtTokenVerifier(), JwtUsernamePasswordAuthenticationFilter.class)
        .authorizeRequests()
        .antMatchers(HttpMethod.GET, "/secured").hasAnyRole("USER","ADMIN")
        .antMatchers(HttpMethod.GET, "/management").hasRole("ADMIN")
        //.antMatchers(HttpMethod.POST, "/authenticate").permitAll()
        .antMatchers("/permitted").permitAll()
        .anyRequest().authenticated();

  }

  // In-memory authentication to authenticate the user i.e. the user credentials are stored in the memory.
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.parentAuthenticationManager(authenticationManagerBean())
        .userDetailsService(userDetailsService)
    .passwordEncoder(passwordEncoder());
  }

  @Override
  @Bean
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
