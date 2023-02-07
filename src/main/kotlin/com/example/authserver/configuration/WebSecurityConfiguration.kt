package com.example.authserver.configuration

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
class WebSecurityConfiguration {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain =
        http.formLogin()
            .and().authorizeRequests().anyRequest().authenticated()
            .and().build()

    @Bean
    fun userDetailsService(): UserDetailsService = InMemoryUserDetailsManager()
        .also {
            it.createUser(
                User
                    .withUsername("u1")
                    .password("pass")
                    .authorities("read")
                    .build()
            )
        }

    @Bean
    fun passwordEncoder(): PasswordEncoder = NoOpPasswordEncoder.getInstance()

}