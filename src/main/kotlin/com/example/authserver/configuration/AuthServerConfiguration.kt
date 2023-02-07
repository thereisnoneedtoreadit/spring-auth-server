package com.example.authserver.configuration

import com.example.authserver.configuration.keys.KeyManager
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings
import org.springframework.security.web.SecurityFilterChain
import java.util.UUID

@Configuration
class AuthServerConfiguration(
    private val keyManager: KeyManager
) {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun securityFilterChainAs(http: HttpSecurity): SecurityFilterChain =
        OAuth2AuthorizationServerConfiguration
            .applyDefaultSecurity(http)
            .let { http.formLogin().and().build() }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository = InMemoryRegisteredClientRepository(
        RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret("secret")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .scope(OidcScopes.OPENID)
            .redirectUri("http://youtube.com")
            .build()
    )

    @Bean
    fun providerSettings(): ProviderSettings = ProviderSettings.builder().build()

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> = JWKSource { j: JWKSelector, _: SecurityContext ->
        j.select(JWKSet(keyManager.rsaKey()))
    }

}