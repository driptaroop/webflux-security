package org.dripto.spring.webfluxsecurity

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.data.jpa.repository.config.EnableJpaRepositories
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.reactive.config.EnableWebFlux

@SpringBootApplication
@EnableJpaRepositories
@EnableWebFlux
class Application{
    @Bean
    fun encoder(): PasswordEncoder = Argon2PasswordEncoder()

    @Bean fun objectMapper(): ObjectMapper = jacksonObjectMapper().findAndRegisterModules()
}

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}
