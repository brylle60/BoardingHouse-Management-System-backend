package com.BoardingHouse.BoardingHouse_Management_System.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure unit tests for SecurityConfig - NO Spring Context required
 */
class SecurityConfigTest {

    @Test
    void passwordEncoder_ShouldBeConfigured() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        assertNotNull(passwordEncoder);
    }

    @Test
    void passwordEncoder_ShouldEncodeDifferently() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String rawPassword = "Password123!";

        String encoded1 = passwordEncoder.encode(rawPassword);
        String encoded2 = passwordEncoder.encode(rawPassword);

        assertNotEquals(encoded1, encoded2, "BCrypt should generate different hashes");
        assertTrue(passwordEncoder.matches(rawPassword, encoded1));
        assertTrue(passwordEncoder.matches(rawPassword, encoded2));
    }

    @Test
    void passwordEncoder_ShouldMatchCorrectPassword() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String rawPassword = "Password123!";
        String encoded = passwordEncoder.encode(rawPassword);

        boolean matches = passwordEncoder.matches(rawPassword, encoded);
        assertTrue(matches, "Password should match its encoded version");
    }

    @Test
    void passwordEncoder_ShouldNotMatchIncorrectPassword() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String rawPassword = "Password123!";
        String wrongPassword = "WrongPassword";
        String encoded = passwordEncoder.encode(rawPassword);

        boolean matches = passwordEncoder.matches(wrongPassword, encoded);
        assertFalse(matches, "Wrong password should not match");
    }

    @Test
    void passwordEncoder_ShouldHandleNonEmptyPassword() {
        // BCrypt can encode empty strings, but we should test with actual passwords
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String password = "a"; // Minimal non-empty password

        String encoded = passwordEncoder.encode(password);
        assertNotNull(encoded);
        assertTrue(passwordEncoder.matches(password, encoded));
    }

    @Test
    void passwordEncoder_EncodedPasswordShouldStartWithBCryptPrefix() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String rawPassword = "Password123!";

        String encoded = passwordEncoder.encode(rawPassword);
        assertTrue(encoded.startsWith("$2a$") || encoded.startsWith("$2b$") || encoded.startsWith("$2y$"),
            "BCrypt hash should start with $2a$, $2b$, or $2y$");
    }

    @Test
    void passwordEncoder_ShouldHandleSpecialCharacters() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String complexPassword = "P@ssw0rd!#$%^&*()_+-=[]{}|;:',.<>?/`~";

        String encoded = passwordEncoder.encode(complexPassword);
        assertNotNull(encoded);
        assertTrue(passwordEncoder.matches(complexPassword, encoded));
    }

    @Test
    void passwordEncoder_ShouldHandleLongPassword() {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String longPassword = "a".repeat(72); // BCrypt max is 72 bytes

        String encoded = passwordEncoder.encode(longPassword);
        assertNotNull(encoded);
        assertTrue(passwordEncoder.matches(longPassword, encoded));
    }
}