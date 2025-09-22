package com.example.demo.controller;

import com.example.demo.model.PasswordResetToken;
import com.example.demo.model.User;
import com.example.demo.payload.request.LoginRequest;
import com.example.demo.payload.request.ResetPasswordRequest;
import com.example.demo.payload.request.SignupRequest;
import com.example.demo.repository.ResetTokenRepository;
import com.example.demo.repository.UserRepository;
import com.example.demo.security.UserDetailsImpl;
import com.example.demo.util.EmailUtil;
import com.example.demo.util.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private ResetTokenRepository tokenRepository;
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private EmailUtil emailUtil;

    @Value("${icurff.app.tokenExprirationSec}")
    private long tokenExpirationSeconds;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        return ResponseEntity.ok(userDetails);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signupRequest) {
        if (userRepository.existsByUsername(signupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Email is already in use!");
        }

        User user = new User(signupRequest.getUsername(),
                signupRequest.getEmail(),
                passwordEncoder.encode(signupRequest.getPassword()));


        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body("Email is not exist");
        }
        User user = userOpt.get();


        tokenRepository.deleteByUserId(user.getId());

        SecureRandom random = new SecureRandom();
        String token = String.valueOf(100000 + random.nextInt(900000));

        PasswordResetToken resetToken = new PasswordResetToken(token, user.getId(), tokenExpirationSeconds);
        tokenRepository.save(resetToken);

        String message = "Your reset token is: " + token;
        emailUtil.sendEmail(email, "Your OTP Code", message);

        return ResponseEntity.ok("Email sent successfully");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
        Optional<PasswordResetToken> tokenOtp = tokenRepository.findByToken(resetPasswordRequest.getToken());

        if (tokenOtp.isEmpty()) {
            return ResponseEntity.badRequest().body("Token is not valid");
        }

        PasswordResetToken resetToken = tokenOtp.get();
        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
            return ResponseEntity.badRequest().body("Token expired");
        }

        User user = userRepository.findById(resetToken.getUserId()).orElse(null);

        if (user == null) {
            return ResponseEntity.badRequest().body("Cant find the user");
        }


        user.setPassword(passwordEncoder.encode(resetPasswordRequest.getPassword()));
        userRepository.save(user);

        tokenRepository.delete(resetToken);

        return ResponseEntity.ok("Password reset successfully");
    }


}
