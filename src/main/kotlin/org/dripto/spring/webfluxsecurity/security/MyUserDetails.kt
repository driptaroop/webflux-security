package org.dripto.spring.webfluxsecurity.security

import org.dripto.spring.webfluxsecurity.controller.Role
import org.dripto.spring.webfluxsecurity.jpa.UserRepositories
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import java.util.UUID

@Service
class MyUserDetailsService(
    private val userRepositories: UserRepositories
): ReactiveUserDetailsService {
    override fun findByUsername(username: String): Mono<UserDetails> {
        return userRepositories.findByUsername(username)?.let {
            Mono.just(MyUserDetails(it.username, it.passwordHash, it.id, it.roles.map { role -> Role.valueOf(role.authority) }.toSet()))
        } ?: throw UsernameNotFoundException("User Not Found").also { println(it) }
    }
}

class MyUserDetails(
    username: String,
    password: String,
    val userId: UUID,
    authorities: Set<Role>
): User(username, password, authorities.map { it.authority() })