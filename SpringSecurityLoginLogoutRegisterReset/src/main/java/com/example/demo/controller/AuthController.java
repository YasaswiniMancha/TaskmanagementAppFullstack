package com.example.demo.controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.example.demo.entity.PasswordHistory;
import com.example.demo.entity.PasswordResetToken;
import com.example.demo.entity.User;
import com.example.demo.entity.UserRole;
import com.example.demo.repository.PasswordHistoryRepository;
import com.example.demo.repository.PasswordResetTokenRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.repository.UserRoleRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Autowired
    private PasswordHistoryRepository passwordHistoryRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JavaMailSender mailSender;

    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        System.out.println("Registering user: " + request.getUsername());
        if (request.getUsername() == null || request.getPassword() == null) {
            throw new IllegalArgumentException("Username and password are required");
        }
        String roleName = request.getRole() != null ? request.getRole().toUpperCase() : "USER";
        if (!roleName.equals("USER") && !roleName.equals("ADMIN") && !roleName.equals("CEO")) {
            throw new IllegalArgumentException("Invalid role: " + roleName);
        }
        User user = new User();
        user.setUsername(request.getUsername());
        String hashedPassword = passwordEncoder.encode(request.getPassword());
        user.setPassword(hashedPassword);
        UserRole userRole = userRoleRepository.findByRole(roleName).orElseGet(() -> {
            UserRole newRole = new UserRole(roleName);
            return userRoleRepository.save(newRole);
        });
        user.setRole(userRole);
        userRepository.save(user);
        PasswordHistory passwordHistory = new PasswordHistory(hashedPassword, user, LocalDateTime.now());
        passwordHistoryRepository.save(passwordHistory);
        System.out.println("User saved: " + user.getUsername() + ", Role: " + roleName);
        return "User registered successfully";
    }

    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestBody ForgotPasswordRequest request) {
        User user = userRepository.findByUsername(request.getUsername()).orElseThrow(() -> {
            System.out.println("Forgot password: User not found: " + request.getUsername());
            return new RuntimeException("User not found");
        });
        String token = UUID.randomUUID().toString();
        PasswordResetToken resetToken = new PasswordResetToken(token, user, LocalDateTime.now().plusHours(1));
        tokenRepository.save(resetToken);
        String resetUrl = "http://localhost:3000/reset-password?token=" + token;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getUsername());
        message.setSubject("Password Reset Request");
        message.setText("To reset your password, click the link below:\n" + resetUrl);
        try {
            mailSender.send(message);
        } catch (Exception e) {
            System.out.println("Mock email sent to " + user.getUsername() + ": " + resetUrl);
        }
        return "Password reset email sent";
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestBody ResetPasswordRequest request) {
        System.out.println("Resetting password for token: " + request.getToken() + ", Role: " + request.getRole());
        if (request.getRole() == null) {
            throw new IllegalArgumentException("Role is required");
        }
        String roleName = request.getRole().toUpperCase();
        if (!roleName.equals("USER") && !roleName.equals("ADMIN") && !roleName.equals("CEO")) {
            throw new IllegalArgumentException("Invalid role: " + roleName);
        }
        PasswordResetToken resetToken = tokenRepository.findByToken(request.getToken())
                .orElseThrow(() -> new RuntimeException("Invalid or expired token"));
        if (resetToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("Token has expired");
        }
        User user = resetToken.getUser();
        // Restrict password reset to the authenticated user's own account
        String authenticatedUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        if (!user.getUsername().equals(authenticatedUsername)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "You can only reset your own password");
        }
        if (user.getRole() == null || !user.getRole().getRole().equals(roleName)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "User does not have role: " + roleName);
        }
        String newPassword = request.getNewPassword();
        String newHashedPassword = passwordEncoder.encode(newPassword);

        List<PasswordHistory> passwordHistory = passwordHistoryRepository.findByUser(user);
        for (PasswordHistory history : passwordHistory) {
            if (passwordEncoder.matches(newPassword, history.getPassword())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Hey, try another password, it seems like you have already used it.");
            }
        }

        PasswordHistory oldPasswordHistory = new PasswordHistory(user.getPassword(), user, LocalDateTime.now());
        passwordHistoryRepository.save(oldPasswordHistory);

        user.setPassword(newHashedPassword);
        userRepository.save(user);
        tokenRepository.delete(resetToken);
        return "Password reset successfully";
    }

    @GetMapping("/profile")
    public Map<String, Object> getProfile() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Fetching profile for user: " + username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username));
        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getUser_id());
        response.put("username", user.getUsername());
        response.put("name", user.getName());
        response.put("phoneNumber", user.getPhoneNumber());
        response.put("address", user.getAddress());
        response.put("about", user.getAbout());
        response.put("location", user.getLocation());
        response.put("role", user.getRole());
        return response;
    }

    @PutMapping("/profile")
    public String updateProfile(@RequestBody User updatedUser) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Updating profile for user: " + username);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username));
        
        // Update username only if not ADMIN
        if (user.getRole() == null || !user.getRole().getRole().equals("ADMIN")) {
            if (updatedUser.getUsername() != null && !updatedUser.getUsername().trim().isEmpty()) {
                user.setUsername(updatedUser.getUsername());
            }
        }
        
        // Update other fields
        user.setName(updatedUser.getName());
        user.setPhoneNumber(updatedUser.getPhoneNumber());
        user.setAddress(updatedUser.getAddress());
        user.setAbout(updatedUser.getAbout());
        user.setLocation(updatedUser.getLocation());
        userRepository.save(user);
        return "Profile updated successfully";
    }

    @GetMapping("/users")
    public List<User> getAllUsers() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Fetching all users by: " + username);
        User requester = userRepository.findByUsername(username).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found: " + username));
        if (requester.getRole() == null || 
            (!requester.getRole().getRole().equals("ADMIN") && !requester.getRole().getRole().equals("CEO"))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Only admins or CEOs can view users");
        }
        List<User> users = userRepository.findAllWithRoles();
        // For ADMIN, filter to show only USER role users
        if (requester.getRole().getRole().equals("ADMIN")) {
            users = users.stream()
                    .filter(user -> user.getRole() != null && user.getRole().getRole().equals("USER"))
                    .collect(Collectors.toList());
        }
        // For CEO, exclude their own details but include USER and ADMIN roles
        if (requester.getRole().getRole().equals("CEO")) {
            users = users.stream()
                    .filter(user -> !user.getUsername().equals(username))
                    .filter(user -> user.getRole() != null && 
                        (user.getRole().getRole().equals("USER") || user.getRole().getRole().equals("ADMIN")))
                    .collect(Collectors.toList());
        }
        System.out.println("Returning " + users.size() + " users for " + username);
        return users;
    }

    @DeleteMapping("/users/{id}")
    @Transactional
    public String deleteUser(@PathVariable Long id) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Deleting user ID: " + id + " by admin: " + username);
        User admin = userRepository.findByUsername(username).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Admin not found: " + username));
        if (admin.getRole() == null || !admin.getRole().getRole().equals("ADMIN")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Only admins can delete users");
        }
        User userToDelete = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found: " + id));
      
        if (userToDelete.getRole() != null && userToDelete.getRole().getRole().equals("CEO")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admins cannot delete CEO users");
        }
        // Restrict deletion to USER role only
        if (userToDelete.getRole() == null || !userToDelete.getRole().getRole().equals("USER")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admins can only delete USER role users");
        }
        // Delete related password history records
        passwordHistoryRepository.deleteByUser(userToDelete);
        userRepository.delete(userToDelete);
        return "User deleted successfully";
    }

    @PostMapping("/admins")
    public String createAdmin(@RequestBody User adminUser) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Creating admin by CEO: " + username);
        User ceo = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "CEO not found: " + username));
        if (ceo.getRole() == null || !ceo.getRole().getRole().equals("CEO")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Only CEOs can create admins");
        }
        if (adminUser.getUsername() == null || adminUser.getPassword() == null) {
            throw new IllegalArgumentException("Username and password are required");
        }
        String hashedPassword = passwordEncoder.encode(adminUser.getPassword());
        adminUser.setPassword(hashedPassword);
        UserRole adminRole = userRoleRepository.findByRole("ADMIN").orElseGet(() -> {
            UserRole newRole = new UserRole("ADMIN");
            return userRoleRepository.save(newRole);
        });
        adminUser.setRole(adminRole);
        userRepository.save(adminUser);
        PasswordHistory passwordHistory = new PasswordHistory(hashedPassword, adminUser, LocalDateTime.now());
        passwordHistoryRepository.save(passwordHistory);
        System.out.println("Admin created: " + adminUser.getUsername());
        return "Admin created successfully";
    }

    @DeleteMapping("/admins/{id}")
    @Transactional
    public String deleteAdmin(@PathVariable Long id) {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        System.out.println("Deleting admin ID: " + id + " by CEO: " + username);
        User ceo = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "CEO not found: " + username));
        if (ceo.getRole() == null || !ceo.getRole().getRole().equals("CEO")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Only CEOs can delete admins");
        }
        User adminToDelete = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Admin not found: " + id));
        if (adminToDelete.getRole() == null || !adminToDelete.getRole().getRole().equals("ADMIN")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User is not an admin");
        }
        // Delete related password history records
        passwordHistoryRepository.deleteByUser(adminToDelete);
        userRepository.delete(adminToDelete);
        System.out.println("Admin deleted successfully: " + adminToDelete.getUsername());
        return "Admin deleted successfully";
    }

    @GetMapping("/users/biodetails")
    public List<User> getUserBioDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        System.out.println("Fetching user bio details by user: " + username + ", Authorities: " + authentication.getAuthorities());
        List<User> users = userRepository.findAllWithRoles();
     // For CEO, exclude their own details
        users = users.stream()
        		.filter(user -> !user.getUsername().equals(username))
                .filter(user -> user.getRole() != null && 
                    (user.getRole().getRole().equals("USER") || user.getRole().getRole().equals("ADMIN")))
                .collect(Collectors.toList());
        System.out.println("Bio details fetched: " + users.size() + " users");
        return users;
    }

    @GetMapping("/debug/authorities")
    public String debugAuthorities() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String result = "User: " + auth.getName() + ", Authorities: " + auth.getAuthorities();
        System.out.println("Debug authorities: " + result);
        return result;
    }
}

class ForgotPasswordRequest {
    private String username;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}

class ResetPasswordRequest {
    private String token;
    private String newPassword;
    private String role;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}

class RegisterRequest {
    private String username;
    private String password;
    private String role;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}