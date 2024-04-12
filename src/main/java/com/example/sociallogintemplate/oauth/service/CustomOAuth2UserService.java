package com.example.sociallogintemplate.oauth.service;

import com.example.sociallogintemplate.api.entity.User;
import com.example.sociallogintemplate.api.repository.UserRepository;
import com.example.sociallogintemplate.oauth.entity.ProviderType;
import com.example.sociallogintemplate.oauth.entity.RoleType;
import com.example.sociallogintemplate.oauth.entity.UserPrincipal;
import com.example.sociallogintemplate.oauth.exception.OAuth2ProviderException;
import com.example.sociallogintemplate.oauth.info.OAuth2UserInfo;
import com.example.sociallogintemplate.oauth.info.OAuth2UserInfoFactory;
import javax.naming.AuthenticationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user = super.loadUser(userRequest);

        try {
            ProviderType providerType = ProviderType.valueOf(userRequest
                    .getClientRegistration()
                    .getRegistrationId()
                    .toUpperCase());

            OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(providerType, user.getAttributes());
            User savedUser = userRepository.findByUserId(userInfo.getId());

            if (savedUser != null) {
                if (providerType != savedUser.getProviderType()) {
                    throw new OAuth2ProviderException(savedUser.getProviderType() + "계정으로 가입하셨습니다."
                            + "해당 플랫폼을 통해 다시 로그인 해 주세요.");
                } // 연동을 시켜버릴까?
                updateUser(savedUser, userInfo);
            } else {
                savedUser = createUser(userInfo, providerType);
            }
            return UserPrincipal.create(savedUser, user.getAttributes());
//        } catch (AuthenticationException e) {
//            throw e;
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e.getCause());
        }
    }

    private User createUser(OAuth2UserInfo userInfo, ProviderType providerType) {
        return User.builder()
                .userId(userInfo.getId())
                .username(userInfo.getName())
                .password("NO_PASS")
                .email(userInfo.getEmail())
                .providerType(providerType)
                .roleType(RoleType.USER)
                .build();
    }

    private User updateUser(User user, OAuth2UserInfo userInfo) {
        if (userInfo.getName() != null && !user.getUsername().equals(userInfo.getName())) {
            user.setUsername(userInfo.getName());
        }
        return user;
    }
}
