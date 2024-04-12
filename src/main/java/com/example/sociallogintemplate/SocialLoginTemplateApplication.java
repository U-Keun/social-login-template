package com.example.sociallogintemplate;

import com.example.sociallogintemplate.config.properties.AppProperties;
import com.example.sociallogintemplate.config.properties.CorsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        CorsProperties.class,
        AppProperties.class
})
public class SocialLoginTemplateApplication {

    public static void main(String[] args) {
        SpringApplication.run(SocialLoginTemplateApplication.class, args);
    }

}
