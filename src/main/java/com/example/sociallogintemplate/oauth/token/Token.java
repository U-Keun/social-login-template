package com.example.sociallogintemplate.oauth.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import java.security.Key;
import java.util.Date;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RequiredArgsConstructor
public class Token {
    @Getter
    private final String token;
    private final Key key;

    private static final Logger logger = LoggerFactory.getLogger(Token.class);
    private static final String AUTHORITIES_KEY = "role";

    Token(String id, Date validity, Key key) {
        this.token = createToken(id, validity);
        this.key = key;
    }

    Token(String id, String role, Date validity, Key key) {
        this.token = createToken(id, role, validity);
        this.key = key;
    }

    private String createToken(String id, Date validity) {
        return Jwts.builder()
                .setSubject(id)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(validity)
                .compact();
    }

    private String createToken(String id, String role, Date validity) {
        return Jwts.builder()
                .setSubject(id)
                .claim(AUTHORITIES_KEY, role)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(validity)
                .compact();
    }

    public boolean validate() {
        return this.getTokenClaims() != null;
    }

    public Claims getTokenClaims() {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (SecurityException e) {
            logger.debug("유효하지 않은 JWT 서명입니다.");
        } catch (MalformedJwtException e) {
            logger.debug("유효하지 않은 JWT 토큰입니다.");
        } catch (ExpiredJwtException e) {
            logger.debug("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.debug("지원하지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.debug("잘못된 JWT 토큰입니다.");
        }
        return null;
    }

    public Claims getExpiredTokenClaims() {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            logger.debug("만료된 JWT 토큰입니다.");
            return e.getClaims();
        }
        return null;
    }
}
