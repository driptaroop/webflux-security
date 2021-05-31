package org.dripto.spring.webfluxsecurity.jpa

import org.dripto.spring.webfluxsecurity.controller.RegistrationController
import org.springframework.security.crypto.password.PasswordEncoder
import java.util.UUID
import javax.persistence.CascadeType
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.FetchType.EAGER
import javax.persistence.FetchType.LAZY
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.JoinTable
import javax.persistence.ManyToMany
import javax.persistence.Table

@Entity
@Table(name = "my_user")
class MyUserEntity(
    @Id
    var id: UUID = UUID.randomUUID(),
    @Column(unique = true)
    var username: String,
    var passwordHash: String,
    var enabled: Boolean,
    @ManyToMany(cascade = [CascadeType.PERSIST, CascadeType.MERGE], fetch = EAGER)
    @JoinTable(
        name = "authority_grant",
        joinColumns = [JoinColumn(name = "user_id")],
        inverseJoinColumns = [JoinColumn(name = "authority_id")]
    )
    var roles: Set<MyUserAuthorities>
) {
    companion object {
        fun from(
            details: RegistrationController.Registration,
            passwordEncoder: PasswordEncoder,
            roles: Set<MyUserAuthorities>
        ): MyUserEntity {
            return MyUserEntity(
                username = details.username,
                passwordHash = passwordEncoder.encode(details.password),
                enabled = true,
                roles = roles
            )
        }
    }
}

@Entity
@Table(name = "authority")
class MyUserAuthorities(
    @Id
    var id: UUID = UUID.randomUUID(),
    @Column(unique = true)
    var authority: String,
    @ManyToMany(fetch = LAZY, mappedBy = "roles")
    var user: Set<MyUserEntity>? = null
)
