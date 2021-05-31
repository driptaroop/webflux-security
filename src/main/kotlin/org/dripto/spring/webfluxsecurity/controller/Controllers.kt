package org.dripto.spring.webfluxsecurity.controller

import kotlinx.coroutines.reactor.awaitSingle
import org.dripto.spring.webfluxsecurity.security.MyUserDetails
import org.springframework.security.core.context.ReactiveSecurityContextHolder
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux

@RestController
@RequestMapping("/user")
class UserController {
    @GetMapping suspend fun page(): String {
        val user = ReactiveSecurityContextHolder.getContext().awaitSingle().authentication.principal as MyUserDetails
        return "hello user: ${user.username}, with id: ${user.userId}"
    }
}

@RestController
@RequestMapping("/admin")
class AdminController {
    @GetMapping suspend fun page() = "hello admin!!"
}

