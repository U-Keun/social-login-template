package com.example.sociallogintemplate.oauth.exception;

public class NotValidTokenException extends RuntimeException {
    public NotValidTokenException() {
        super("토큰이 유효하지 않습니다.");
    }
}
