package com.example.sociallogintemplate.common;

import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class APIResponse<T> {

    private final static int SUCCESS = 200;
    private final static int NOT_FOUND = 400;
    private final static int FAILED = 500;
    private final static String SUCCESS_MESSAGE = "SUCCESS";
    private final static String NOT_FOUND_MESSAGE = "NOT FOUND";
    private final static String FAILED_MESSAGE = "서버에서 오류가 발생하였습니다.";
    private final static String INVALID_ACCESS_TOKEN = "Access Token이 유효하지 않습니다.";
    private final static String INVALID_REFRESH_TOKEN = "Refresh Token이 유효하지 않습니다.";
    private final static String NOT_EXPIRED_TOKEN_YET = "Token이 아직 만료되지 않았습니다.";

    private final APIResponseHeader header;
    private final Map<String, T> body;

    public static <T> APIResponse<T> success(String name, T body) {
        Map<String, T> map = new HashMap<>();
        map.put(name, body);

        return new APIResponse<>(new APIResponseHeader(SUCCESS, SUCCESS_MESSAGE), map);
    }

    public static <T> APIResponse<T> fail() {
        return new APIResponse<>(new APIResponseHeader(FAILED, FAILED_MESSAGE), null);
    }

    public static <T> APIResponse<T> invalidAccessToken() {
        return new APIResponse<>(new APIResponseHeader(FAILED, INVALID_ACCESS_TOKEN), null);
    }

    public static <T> APIResponse<T> invalidRefreshToken() {
        return new APIResponse<>(new APIResponseHeader(FAILED, INVALID_REFRESH_TOKEN), null);
    }

    public static <T> APIResponse<T> notExpiredTokenYet() {
        return new APIResponse<>(new APIResponseHeader(FAILED, NOT_EXPIRED_TOKEN_YET), null);
    }
}
