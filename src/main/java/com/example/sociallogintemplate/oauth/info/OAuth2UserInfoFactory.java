package com.example.sociallogintemplate.oauth.info;

import com.example.sociallogintemplate.oauth.entity.ProviderType;
import com.example.sociallogintemplate.oauth.info.platform.AppleOAuth2UserInfo;
import com.example.sociallogintemplate.oauth.info.platform.GoogleOAuth2UserInfo;
import com.example.sociallogintemplate.oauth.info.platform.KakaoOAuth2UserInfo;
import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(ProviderType providerType, Map<String, Object> attributes) {
        switch (providerType) {
            case APPLE: return new AppleOAuth2UserInfo(attributes);
            case GOOGLE: return new GoogleOAuth2UserInfo(attributes);
            case KAKAO: return new KakaoOAuth2UserInfo(attributes);
            default: throw new IllegalArgumentException("유효하지 않은 ProviderType입니다.");
        }
    }
}
