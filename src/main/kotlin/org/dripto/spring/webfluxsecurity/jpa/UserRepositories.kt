package org.dripto.spring.webfluxsecurity.jpa

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserRepositories: JpaRepository<MyUserEntity, UUID> {
    fun findByUsername(username: String): MyUserEntity?
}

interface AuthorityRepository: JpaRepository<MyUserAuthorities, UUID>{
    fun existsByAuthority(authority: String): Boolean
    fun findByAuthority(authority: String): MyUserAuthorities?
    fun findOrCreateByAuthority(authority: String): MyUserAuthorities =
        if (existsByAuthority(authority)) {
            findByAuthority(authority) ?: throw IllegalStateException("hoche ta ki")
        } else {
            save(MyUserAuthorities(authority = authority))
        }
}