package com.example.sociallogintemplate.oauth.token;

import com.example.sociallogintemplate.oauth.exception.NotValidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class TokenProvider {
    private final Key key;
    private static final String AUTHORITIES_KEY = "role";

    public TokenProvider(String secret) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Token createToken(String id, Date validity) {
        return new Token(id, validity, key);
    }

    public Token createToken(String id, String role, Date validity) {
        return new Token(id, role, validity, key);
    }

    public Token convertToken(String token) {
        return new Token(token, key);
    }

    public Authentication getAuthentication(Token token) {
        if (token.validate()) {
            Claims claims = token.getTokenClaims();
            Collection<? extends GrantedAuthority> authorities =
                    Arrays.stream(new String[]{claims.get(AUTHORITIES_KEY).toString()})
                            .map(SimpleGrantedAuthority::new)
                            .toList();

            User principal = new User(claims.getSubject(), "", authorities);

            return new UsernamePasswordAuthenticationToken(principal, token, authorities);
        } else {
            throw new NotValidTokenException();
        }
    }
}
