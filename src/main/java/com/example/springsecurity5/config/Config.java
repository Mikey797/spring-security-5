package com.example.springsecurity5.config;

import com.example.springsecurity5.security.filters.CustomAuthenticationFilter;
import com.example.springsecurity5.security.providers.CustomAuthProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.swing.text.html.HTML;

@Configuration
public class Config extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomAuthenticationFilter filter;

    @Autowired
    private CustomAuthProvider customAuthProvider;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /*
        in filter chain there are in order. starts from 100 ..200 and so on
        you have to put your custom authentication filter precisely where
        your basic authentication filter was. so we use http.filterAt()....

         */
        http.addFilterAt(filter, BasicAuthenticationFilter.class);
        http.authorizeRequests().anyRequest().permitAll();
    }

    /*
            we need to put in to the context because we use AuthenticationManager
            in our custom authentication filter
             */
    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
}
