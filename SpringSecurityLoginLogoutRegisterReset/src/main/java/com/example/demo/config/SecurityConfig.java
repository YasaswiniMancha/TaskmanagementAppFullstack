package com.example.demo.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.example.demo.service.UserDetailsServiceImpl;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("Configuring SecurityFilterChain with UserDetailsService: " + userDetailsService);
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .expiredUrl("/api/auth/login")
            )
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/api/auth/register", "/api/auth/forgot-password", "/api/auth/reset-password", "/api/auth/login", "/api/auth/logout", "/error").permitAll()
                // Debug endpoint
                .requestMatchers("/api/auth/debug/authorities").authenticated()
                // CEO-specific endpoint
                .requestMatchers("/api/auth/users/biodetails", "/api/auth/admins", "/api/auth/admins/**").hasAnyAuthority("ROLE_CEO")                // Admin and CEO endpoints
                .requestMatchers("/api/auth/users", "/api/auth/users/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_CEO")
                .requestMatchers("/api/auth/admins", "/api/auth/admins/**").hasAnyAuthority("ROLE_CEO")
                // Other endpoints
                .requestMatchers("/api/auth/profile").authenticated()
                .requestMatchers("/api/tasks/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN", "ROLE_CEO")
                // Catch-all for other requests
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginProcessingUrl("/api/auth/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler((request, response, authentication) -> {
                    System.out.println("Login successful for user: " + authentication.getName() + ", Authorities: " + authentication.getAuthorities());
                    response.setStatus(200);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"message\": \"Login successful\", \"username\": \"" + authentication.getName() + "\"}");
                    response.getWriter().flush();
                })
                .failureHandler((request, response, exception) -> {
                    System.out.println("Login failed: " + exception.getMessage() + ", Username: " + request.getParameter("username"));
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Login failed: " + exception.getMessage() + "\"}");
                    response.getWriter().flush();
                })
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessUrl("/api/auth/login")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .logoutSuccessHandler((request, response, authentication) -> {
                    System.out.println("Logout successful for user: " + (authentication != null ? authentication.getName() : "none"));
                    response.setStatus(200);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"message\": \"Logout successful\"}");
                    response.getWriter().flush();
                })
                .permitAll()
            )
            .userDetailsService(userDetailsService)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    System.out.println("Authentication error: " + authException.getMessage() + ", URI: " + request.getRequestURI());
                    response.setStatus(401);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Unauthorized: " + authException.getMessage() + "\"}");
                    response.getWriter().flush();
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    String username = SecurityContextHolder.getContext().getAuthentication() != null 
                        ? SecurityContextHolder.getContext().getAuthentication().getName() 
                        : "anonymous";
                    System.out.println("Access denied for user: " + username + ", URI: " + request.getRequestURI() + ", Authorities: " + 
                        (SecurityContextHolder.getContext().getAuthentication() != null 
                            ? SecurityContextHolder.getContext().getAuthentication().getAuthorities() 
                            : "none") + ", Reason: " + accessDeniedException.getMessage());
                    response.setStatus(403);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Forbidden\", \"message\": \"" + accessDeniedException.getMessage() + "\"}");
                    response.getWriter().flush();
                })
            );
        // Debug security configuration
        System.out.println("Security rules configured for /api/auth/users: hasAnyAuthority('ROLE_ADMIN', 'ROLE_CEO')");
        System.out.println("Security rules configured for /api/auth/users/biodetails: hasAnyAuthority('ROLE_CEO')");
        System.out.println("Security rules configured for /api/auth/admins: hasAnyAuthority('ROLE_CEO')");
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Set-Cookie"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
}