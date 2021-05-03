package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails studentUserOne = User.builder()
                .username("student1")
                .password(passwordEncoder.encode("password"))
                .roles(STUDENT.name())// ROLE_STUDENT
                .build();
        UserDetails adminUserOne = User.builder()
                .username("admin1")
                .password(passwordEncoder.encode("password123"))
                .roles(ADMIN.name())// ROLE_ADMIN
                .build();
        UserDetails adminUserTwo = User.builder()
                .username("admin2")
                .password(passwordEncoder.encode("password456"))
                .roles(ADMINTRAINEE.name())// ROLE_ADMINTRAINEE
                .build();

        return new InMemoryUserDetailsManager(
                studentUserOne,
                adminUserOne,
                adminUserTwo
        );
    }
}
