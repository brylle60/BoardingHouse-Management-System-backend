package com.BoardingHouse.BoardingHouse_Management_System.service.auth;

import com.BoardingHouse.BoardingHouse_Management_System.config.JwtConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtConfig jwtConfig;

    @InjectMocks
    private AuthenticationService authenticationService;

    @Mock
    private Authentication authentication;

    private String testUsername;
    private String testPassword;

    @BeforeEach
    void setUp() {
        testUsername = "testuser";
        testPassword = "Password123!";
    }

    @Test
    void authenticate_WithValidCredentials_ShouldReturnAuthentication() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);

        // Act
        Authentication result = authenticationService.authenticate(testUsername, testPassword);

        // Assert
        assertNotNull(result);
        assertEquals(authentication, result);
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void authenticate_WithInvalidCredentials_ShouldThrowException() {
        // Arrange
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Invalid credentials"));

        // Act & Assert
        assertThrows(BadCredentialsException.class, () -> {
            authenticationService.authenticate(testUsername, "wrongpassword");
        });

        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void authenticate_WithNullUsername_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            authenticationService.authenticate(null, testPassword);
        });

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void authenticate_WithEmptyPassword_ShouldThrowException() {
        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            authenticationService.authenticate(testUsername, "");
        });

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void authenticate_WithBlankCredentials_ShouldThrowException() {
        // Arrange & Act & Assert
        assertThrows(IllegalArgumentException.class, () -> {
            authenticationService.authenticate("   ", "   ");
        });

        verify(authenticationManager, never()).authenticate(any());
    }
}