package com.example.sociallogintemplate.common;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class APIResponseHeader {
    private int code;
    private String message;
}
