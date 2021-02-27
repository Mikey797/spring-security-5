package com.example.springsecurity5.security.providers;

import com.example.springsecurity5.security.authentication.CustomAuthentication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthProvider implements AuthenticationProvider {

    @Value("${key}")
    private String key;

    @Override
    public Authentication authenticate(Authentication authentication) {
        String requestKey = authentication.getName();
        if (requestKey.equals(key)) {
            return new CustomAuthentication(null, null, null);
        } else {
            throw new BadCredentialsException("Bad Credentials !");
        }
    }

    /*
    tells authentication manager if this authentication provider supports some kind
     of an authentication - custom authentiaction class
     */
    @Override
    public boolean supports(Class<?> aClass) {
        return CustomAuthentication.class.equals(aClass);
    }
}
