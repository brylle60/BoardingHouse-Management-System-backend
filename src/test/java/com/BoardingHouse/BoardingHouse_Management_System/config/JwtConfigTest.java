package com.BoardingHouse.BoardingHouse_Management_System.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure unit tests for JwtConfig - NO Spring Context required
 */
class JwtConfigTest {

    private JwtConfig jwtConfig;
    private UserDetails userDetails;
    private String testUsername;

    @BeforeEach
    void setUp() {
        // Manually create JwtConfig instance
        jwtConfig = new JwtConfig();
        
        // Set properties manually
        jwtConfig.setSecret("3cfa76ef14937c1c0ea519f8fc057a80fcd04a7420f8e8bcd0a7567c272e007b");
        jwtConfig.setExpiration(86400000L);
        jwtConfig.setRefreshExpiration(604800000L);
        
        testUsername = "testuser";
        userDetails = new User(
            testUsername,
            "password",
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Test
    void generateToken_ShouldReturnNonNullToken() {
        String token = jwtConfig.generateToken(userDetails);
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateToken_ShouldContainUsername() {
        String token = jwtConfig.generateToken(userDetails);
        String extractedUsername = jwtConfig.getUsernameFromToken(token);
        assertEquals(testUsername, extractedUsername);
    }

    @Test
    void getUsernameFromToken_ShouldExtractCorrectUsername() {
        String token = jwtConfig.generateToken(userDetails);
        String extractedUsername = jwtConfig.getUsernameFromToken(token);
        assertEquals(testUsername, extractedUsername);
    }

    @Test
    void getExpirationDateFromToken_ShouldReturnFutureDate() {
        String token = jwtConfig.generateToken(userDetails);
        Date expirationDate = jwtConfig.getExpirationDateFromToken(token);
        assertNotNull(expirationDate);
        assertTrue(expirationDate.after(new Date()));
    }

    @Test
    void validateToken_WithValidToken_ShouldReturnTrue() {
        String token = jwtConfig.generateToken(userDetails);
        boolean isValid = jwtConfig.validateToken(token, userDetails);
        assertTrue(isValid);
    }

    @Test
    void validateToken_WithDifferentUsername_ShouldReturnFalse() {
        String token = jwtConfig.generateToken(userDetails);
        UserDetails differentUser = new User(
            "differentuser",
            "password",
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );
        boolean isValid = jwtConfig.validateToken(token, differentUser);
        assertFalse(isValid);
    }

    @Test
    void validateToken_WithInvalidToken_ShouldThrowException() {
        String invalidToken = "invalid.token.here";
        assertThrows(MalformedJwtException.class, () -> {
            jwtConfig.validateToken(invalidToken, userDetails);
        });
    }

    @Test
    void validateToken_WithTamperedToken_ShouldThrowException() {
        String token = jwtConfig.generateToken(userDetails);
        String tamperedToken = token + "tampered";
        assertThrows(SignatureException.class, () -> {
            jwtConfig.validateToken(tamperedToken, userDetails);
        });
    }

    @Test
    void generateRefreshToken_ShouldReturnNonNullToken() {
        String refreshToken = jwtConfig.generateRefreshToken(userDetails);
        assertNotNull(refreshToken);
        assertFalse(refreshToken.isEmpty());
    }

    @Test
    void generateRefreshToken_ShouldContainUsername() {
        String refreshToken = jwtConfig.generateRefreshToken(userDetails);
        String extractedUsername = jwtConfig.getUsernameFromToken(refreshToken);
        assertEquals(testUsername, extractedUsername);
    }

    @Test
    void refreshToken_ShouldHaveLongerExpiration() {
        String accessToken = jwtConfig.generateToken(userDetails);
        String refreshToken = jwtConfig.generateRefreshToken(userDetails);
        Date accessTokenExpiry = jwtConfig.getExpirationDateFromToken(accessToken);
        Date refreshTokenExpiry = jwtConfig.getExpirationDateFromToken(refreshToken);
        assertTrue(refreshTokenExpiry.after(accessTokenExpiry));
    }

    @Test
    void getClaimFromToken_ShouldExtractSubject() {
        String token = jwtConfig.generateToken(userDetails);
        String subject = jwtConfig.getClaimFromToken(token, Claims::getSubject);
        assertEquals(testUsername, subject);
    }

    @Test
    void generateToken_WithExtraClaims_ShouldIncludeClaims() {
        java.util.Map<String, Object> extraClaims = new java.util.HashMap<>();
        extraClaims.put("role", "ADMIN");
        extraClaims.put("userId", 123);

        String token = jwtConfig.generateToken(extraClaims, userDetails);
        assertNotNull(token);
        
        Claims claims = jwtConfig.getClaimFromToken(token, claims1 -> claims1);
        assertEquals("ADMIN", claims.get("role"));
        assertEquals(123, claims.get("userId"));
    }

    @Test
    void twoTokensForSameUser_ShouldBeDifferent() throws InterruptedException {
        String token1 = jwtConfig.generateToken(userDetails);
        Thread.sleep(1000); // Wait 1 second to ensure different issuedAt timestamp
        String token2 = jwtConfig.generateToken(userDetails);
        
        // Tokens should be different because they have different issuedAt times
        assertNotEquals(token1, token2, "Tokens should be different due to different timestamps");
    }
}