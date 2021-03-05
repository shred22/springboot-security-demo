package com.spring.security.demo.service;

import com.spring.security.demo.model.UserDetailsImpl;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService
{

  /**
   *
   * This method can talk to a real Database for loading users
   *
   * @param username
   * @return
   * @throws UsernameNotFoundException
   */


  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return new UserDetailsImpl(username);
  }
}
