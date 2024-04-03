package com.example.sociallogintemplate.jwt;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class TokenProviderTest {
    private TokenProvider tokenProvider;
    Authentication authentication = new UsernamePasswordAuthenticationToken(
            new User("user", "", Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))),
            "password",
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
    );
    @BeforeEach
    public void setUp() {
        tokenProvider = new TokenProvider("1924c33b3a27b6bcc5ab5d91e7490799258991ce2113842fbe65711977c49211041d0da8036c5f7bb8157349f44f8eab4ade861f2866ac1532bc1a7fdd1ef1df", 1800000);
        tokenProvider.afterPropertiesSet();
    }

    @Test
    void 토큰_생성하기() {
        String token = tokenProvider.createToken(authentication);

        assertThat(token).isNotNull();
    }

    @Test
    void 토큰으로부터_인증_객체_얻기() {
        String token = tokenProvider.createToken(authentication);

        Authentication authenticationFromToken = tokenProvider.getAuthentication(token);

        assertThat(authenticationFromToken).isNotNull();
        assertThat(authenticationFromToken.getName()).isEqualTo(authentication.getName());
    }

    @Nested
    class 토큰_유효성_검사 {
        @Test
        void 유효한_토큰이_검증되었을_때() {
            String token = tokenProvider.createToken(authentication);

            boolean isValid = tokenProvider.validateToken(token);

            assertThat(isValid).isTrue();
        }

        @Test
        void 유효하지_않은_토큰이_검증되었을_때() {
            String token = "invalid token";

            boolean isValid = tokenProvider.validateToken(token);

            assertThat(isValid).isFalse();
        }
    }

}