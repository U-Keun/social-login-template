package com.example.sociallogintemplate.oauth.util;

import jakarta.servlet.http.HttpServletRequest;

public class HeaderUtil {
    private static final String TOKEN_PREFIX = "Bearer ";

    public static String getToken(HttpServletRequest request, String division) {
        String header = request.getHeader(division);

        if (header != null && header.startsWith(TOKEN_PREFIX)) {
            return header.substring(TOKEN_PREFIX.length());
        }

        return null;
    }
}
