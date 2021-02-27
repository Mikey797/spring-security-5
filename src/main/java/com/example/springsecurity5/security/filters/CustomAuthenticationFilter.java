package com.example.springsecurity5.security.filters;

import com.example.springsecurity5.security.authentication.CustomAuthentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/*
in spring you can directly implement java default servlet filter
 */
@Component
public class CustomAuthenticationFilter implements Filter {

    @Autowired
    private AuthenticationManager manager;

    /*
       here you are intercepting servletRequest and servletResponse and change them
       and filter chain allows you to delegate to the next item of the filter chain
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws
            IOException, ServletException {
        var httpRequest = (HttpServletRequest) servletRequest;
        var httpResponse = (HttpServletResponse) servletResponse;
        String authorization = httpRequest.getHeader("Authorization");
        /*
         you have to delegate to "AuthenticationManager" after authentication filter
         here we need an fully authenticated object to pass here for authentication manager
         in order it to process and return an authentication if it is fully authenticated or
         it will throw an AAuthentication exception. for the sake of demonstration
         we will use UserNamePasswordAuthenticationToken which implements Authentication contract
         */
        try {
            Authentication authenticate = manager.authenticate(new CustomAuthentication(authorization, null));
            if (authenticate.isAuthenticated()) {
                SecurityContextHolder.getContext().setAuthentication(authenticate);
                // this is how we delegate to the next item in the filter chain
                filterChain.doFilter(servletRequest, servletResponse);
            } else {
                httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            }
        } catch (AuthenticationException e) {
            httpResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }

    }
}
