package com.spring.security.demo.config;

import com.spring.security.demo.provider.CustomAuthenticationProvider;

import javax.sql.DataSource;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//@EnableWebSecurity
@Slf4j
public class JpaWebSecurityconfig extends WebSecurityConfigurerAdapter {

  private final CustomAuthenticationProvider authenticationProvider;
  private final UserDetailsService userDetailsService;


  private  JpaWebSecurityconfig(CustomAuthenticationProvider authenticationProvider, UserDetailsService userDetailsService) {
    this.authenticationProvider = authenticationProvider;
    this.userDetailsService = userDetailsService;
  }


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info("Using default configure(HttpSecurity). "
        + "If subclassed this will potentially override subclass configure(HttpSecurity).");
    http.authorizeRequests()
        .antMatchers(HttpMethod.GET, "/secured").hasAnyRole("USER","ADMIN")
        .antMatchers(HttpMethod.GET, "/management").hasRole("ADMIN")
        .antMatchers("/permitted").permitAll()
        .anyRequest().authenticated()
        .and()
        .formLogin();
  }

  // In-memory authentication to authenticate the user i.e. the user credentials are stored in the memory.
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
  }


  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
