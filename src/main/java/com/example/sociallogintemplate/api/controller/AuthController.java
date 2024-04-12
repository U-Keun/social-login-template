package com.example.sociallogintemplate.api.controller;

import com.example.sociallogintemplate.api.entity.RefreshToken;
import com.example.sociallogintemplate.api.repository.RefreshTokenRepository;
import com.example.sociallogintemplate.common.APIResponse;
import com.example.sociallogintemplate.config.properties.AppProperties;
import com.example.sociallogintemplate.oauth.entity.RoleType;
import com.example.sociallogintemplate.oauth.token.Token;
import com.example.sociallogintemplate.oauth.token.TokenProvider;
import com.example.sociallogintemplate.oauth.util.HeaderUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AppProperties appProperties;
    private final TokenProvider tokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    private static final long UPDATE_TOKEN_STRATEGY = 259200000; // 3일
    private static final String ACCESS_TOKEN = "access_token";
    private static final String REFRESH_TOKEN = "refresh_token";

    @PostMapping("/refresh")
    public APIResponse refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = HeaderUtil.getToken(request, ACCESS_TOKEN);
        Token authToken = tokenProvider.convertToken(accessToken);
        if (!authToken.validate()) {
            return APIResponse.invalidRefreshToken();
        }

        Claims claims = authToken.getExpiredTokenClaims();
        if (claims == null) {
            return APIResponse.notExpiredTokenYet();
        }

        String userId = claims.getSubject();
        RoleType roleType = RoleType.of(claims.get("role", String.class));

        String refreshToken = HeaderUtil.getToken(request, REFRESH_TOKEN);
        Token authRefreshToken = tokenProvider.convertToken(refreshToken);

        if (authRefreshToken.validate()) {
            return APIResponse.invalidRefreshToken();
        }

        Optional<RefreshToken> searchedRefreshToken = refreshTokenRepository.findByUserId(userId);
        RefreshToken userRefreshToken;
        if (searchedRefreshToken.isEmpty()) {
            return APIResponse.invalidRefreshToken();
        }
        userRefreshToken = searchedRefreshToken.get();

        Date now = new Date();
        Token newAccessToken = tokenProvider.createToken(
                userId,
                roleType.getCode(),
                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
        );

        long validTime = authRefreshToken.getTokenClaims().getExpiration().getTime() - now.getTime();

        if (validTime <= UPDATE_TOKEN_STRATEGY) {
            long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

            authRefreshToken = tokenProvider.createToken(
                    appProperties.getAuth().getTokenSecret(),
                    new Date(now.getTime() + refreshTokenExpiry)
            );

            userRefreshToken.updateRefreshToken(authRefreshToken.getToken());
            refreshTokenRepository.save(userRefreshToken);
        }

        Map<String, String> tokens = new HashMap<>();
        tokens.put(ACCESS_TOKEN, newAccessToken.getToken());
        tokens.put(REFRESH_TOKEN, userRefreshToken.getRefreshToken());

        return APIResponse.success("tokens", tokens);
    }
}
