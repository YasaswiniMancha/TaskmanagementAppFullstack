package com.example.demo.service;

import com.example.demo.entity.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("Loading user: '" + (username != null ? username : "null") + "'");
        if (username == null || username.trim().isEmpty()) {
            System.out.println("Empty username provided");
            throw new UsernameNotFoundException("Username cannot be empty");
        }
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    System.out.println("User not found: " + username);
                    return new UsernameNotFoundException("User not found: " + username);
                });
        String roleName = user.getRole() != null ? user.getRole().getRole() : "USER";
        System.out.println("Found user: " + user.getUsername() + ", Role: " + roleName + ", Authority: ROLE_" + roleName);
        System.out.println("Raw role from database: " + (user.getRole() != null ? user.getRole().getRole() : "null"));
        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(roleName)
                .build();
        System.out.println("UserDetails authorities: " + userDetails.getAuthorities());
        return userDetails;
    }
}