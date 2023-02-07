package com.example.authserver.configuration.keys

import com.nimbusds.jose.jwk.RSAKey
import org.springframework.stereotype.Component
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

@Component
class KeyManager {

    fun rsaKey(): RSAKey =
        KeyPairGenerator
            .getInstance("RSA")
            .also { it.initialize(2048) }
            .generateKeyPair()
            .let {
                RSAKey
                    .Builder(it.public as RSAPublicKey)
                    .privateKey(it.private as RSAPrivateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build()
            }

}