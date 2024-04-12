package com.example.sociallogintemplate.oauth.handler;

import com.example.sociallogintemplate.api.entity.RefreshToken;
import com.example.sociallogintemplate.api.repository.RefreshTokenRepository;
import com.example.sociallogintemplate.config.properties.AppProperties;
import com.example.sociallogintemplate.oauth.entity.ProviderType;
import com.example.sociallogintemplate.oauth.entity.RoleType;
import com.example.sociallogintemplate.oauth.info.OAuth2UserInfo;
import com.example.sociallogintemplate.oauth.info.OAuth2UserInfoFactory;
import com.example.sociallogintemplate.oauth.token.Token;
import com.example.sociallogintemplate.oauth.token.TokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private final AppProperties appProperties;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        clearAuthenticationAttributes(request);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        String redirectUri = request.getParameter("redirect-uri");
        if (redirectUri.isEmpty() && !isAuthorizedRedirectUri(redirectUri)) {
            throw new IllegalArgumentException("접근이 허용되지 않는 Redirect URI입니다.");
        }

        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        ProviderType providerType = ProviderType.valueOf(authToken.getAuthorizedClientRegistrationId().toUpperCase());

        OidcUser user = (OidcUser) authentication.getPrincipal();
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());
        Collection<? extends GrantedAuthority> authorities = user.getAuthorities();

        RoleType roleType = hasAuthority(authorities, RoleType.ADMIN.getCode()) ? RoleType.ADMIN : RoleType.USER;

        Date now = new Date();
        Token accessToken = tokenProvider.createToken(
                userInfo.getId(),
                roleType.getCode(),
                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
        );

        long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();

        Token refreshToken = tokenProvider.createToken(
                appProperties.getAuth().getTokenSecret(),
                new Date(now.getTime() + refreshTokenExpiry)
        );

        Optional<RefreshToken> searchedRefreshToken = refreshTokenRepository.findByUserId(userInfo.getId());
        RefreshToken userRefreshToken;
        if (searchedRefreshToken.isEmpty()) {
            String uuid = UUID.randomUUID().toString();
            userRefreshToken = new RefreshToken(uuid, userInfo.getId(), refreshToken.getToken());
            refreshTokenRepository.save(userRefreshToken);
        } else {
            userRefreshToken = searchedRefreshToken.get();
            userRefreshToken.updateRefreshToken(refreshToken.getToken());
        }

        response.addHeader("refresh_token", refreshToken.getToken());

        return UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", accessToken.getToken())
                .build()
                .toUriString();
    }

    private boolean hasAuthority(Collection<? extends GrantedAuthority> authorities, String authority) {
        if (authorities == null) {
            return false;
        }

        for (GrantedAuthority grantedAuthority : authorities) {
            if (authority.equals(grantedAuthority.getAuthority())) {
                return true;
            }
        }

        return false;
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOauth2().getAuthorizedRedirectUris().stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    return authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort();
                });
    }
}
