package org.dripto.spring.webfluxsecurity.security

import org.dripto.spring.webfluxsecurity.security.filter.JwtFilter
import org.springframework.context.annotation.Bean
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository

@EnableWebFluxSecurity
class SecurityConfig(
    val jwtFilter: JwtFilter
) {

    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http.apply {
            authorizeExchange {
                it.pathMatchers("/h2-console/**").permitAll()
                it.pathMatchers("/registration/token").hasAnyRole("USER", "ADMIN")
                it.pathMatchers("/registration/**").permitAll()
                it.pathMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                it.pathMatchers("/admin/**").hasRole("ADMIN")
                it.pathMatchers("/").permitAll()
            }
            securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            addFilterBefore(jwtFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            csrf { it.disable() }
            httpBasic()
        }.build()
    }
}

