package com.spring.security.demo.config;

import com.spring.security.demo.provider.CustomAuthenticationProvider;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//@EnableWebSecurity
@Slf4j
public class WebSecurityconfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private CustomAuthenticationProvider authenticationProvider;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info("Using default configure(HttpSecurity). "
        + "If subclassed this will potentially override subclass configure(HttpSecurity).");
    http.authorizeRequests()
        .antMatchers("/permitted").permitAll()
        .and()
        .authorizeRequests()
        .antMatchers(HttpMethod.GET, "/secured").hasRole("USER")
        .antMatchers(HttpMethod.GET, "/management").hasRole("ADMIN")
        .anyRequest().authenticated()
        .and()
        .formLogin();
  }

  // In-memory authentication to authenticate the user i.e. the user credentials are stored in the memory.
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//        .passwordEncoder(passwordEncoder())
//        .withUser("user")
//        .password(passwordEncoder().encode("password"))
//        .roles("USER")
//        .and()
//        .withUser("admin")
//        .password(passwordEncoder().encode("password"))
//        .roles("ADMIN");

        auth.authenticationProvider(authenticationProvider);
  }


  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
