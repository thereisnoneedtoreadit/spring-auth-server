package com.example.authserver.configuration

import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

@Configuration
class SecurityConfiguration {

    @Bean
    @Order(1)
    @Throws(Exception::class)
    fun asSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer::class.java).oidc(Customizer.withDefaults())
        http.exceptionHandling { e: ExceptionHandlingConfigurer<HttpSecurity?> ->
            e
                .authenticationEntryPoint(LoginUrlAuthenticationEntryPoint("/login"))
        }
        return http.build()
    }

    @Bean
    @Order(2)
    @Throws(Exception::class)
    fun appSecurityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        http
            .formLogin()
            .and()
            .authorizeHttpRequests().anyRequest().authenticated()
        return http.build()
    }

    @Bean
    fun userDetailsService(): UserDetailsService? {
        val user1 = User.withUsername("user")
            .password("password")
            .authorities("read")
            .build()
        return InMemoryUserDetailsManager(user1)
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder? {
        return NoOpPasswordEncoder.getInstance()
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository? {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret("secret")
            .scope("read")
            .redirectUri("https://oidcdebugger.com/debug")
            .redirectUri("https://oauthdebugger.com/debug")
            .redirectUri("https://springone.io/authorized")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings? {
        return AuthorizationServerSettings.builder().build()
    }

    @Bean
    fun tokenSettings(): TokenSettings? {
        return TokenSettings.builder().build()
    }

    @Bean
    fun clientSettings(): ClientSettings? {
        return ClientSettings.builder()
            .requireAuthorizationConsent(false)
            .requireProofKey(false)
            .build()
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext?>? {
        val rsaKey = generateRsa()
        val jwkSet = JWKSet(rsaKey)
        return JWKSource { jwkSelector: JWKSelector, securityContext: SecurityContext? ->
            jwkSelector.select(
                jwkSet
            )
        }
    }

    fun generateRsa(): RSAKey {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        return RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build()
    }

    fun generateRsaKey(): KeyPair {
        val keyPair: KeyPair
        keyPair = try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }
        return keyPair
    }


}