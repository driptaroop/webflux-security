package org.dripto.spring.webfluxsecurity.security.filter

import org.dripto.spring.webfluxsecurity.security.MyUserDetails
import org.dripto.spring.webfluxsecurity.security.MyUserDetailsService
import org.dripto.spring.webfluxsecurity.security.jwt.JwtUtils
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.server.WebFilter
import org.springframework.web.server.WebFilterChain
import reactor.core.publisher.Mono

@Component
class JwtFilter(
    val userDetailsService: MyUserDetailsService
) : WebFilter {
    override fun filter(exchange: ServerWebExchange, chain: WebFilterChain): Mono<Void> {
        val authHeader: String? = exchange.request.headers["Authorization"]?.first()
        return if (authHeader != null && authHeader.startsWith("Bearer")) {
            processAuthHeader(authHeader)
                .flatMap {
                    chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(it))
                }
        } else {
            chain.filter(exchange)
        }
    }

    private fun processAuthHeader(authHeader: String): Mono<UsernamePasswordAuthenticationToken> {
        val jwt: String = authHeader.substring(7)
        val username: String? = JwtUtils.extractUserName(jwt)
        return if (username != null && SecurityContextHolder.getContext().authentication == null) {
            validateToken(jwt, username)
        } else {
            throw BadCredentialsException("invalid credentials")
        }
    }

    private fun validateToken(jwt: String, username: String): Mono<UsernamePasswordAuthenticationToken> {
        val user = userDetailsService.findByUsername(username).map { it as MyUserDetails }
        return user.map {
            if (JwtUtils.validate(jwt, it)) {
                setupAuth(it)
            } else {
                throw BadCredentialsException("invalid credentials")
            }
        }
    }

    private fun setupAuth(user: MyUserDetails): UsernamePasswordAuthenticationToken =
        UsernamePasswordAuthenticationToken(user, user.password, user.authorities)
}