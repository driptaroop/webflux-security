package org.dripto.spring.webfluxsecurity.security.jwt

import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtParser
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm.HS256
import io.jsonwebtoken.security.Keys
import org.dripto.spring.webfluxsecurity.security.MyUserDetails
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Date
import javax.crypto.SecretKey

class JwtUtils {
    companion object {
        private val key: SecretKey = Keys.secretKeyFor(HS256)
        private val parser: JwtParser = Jwts.parserBuilder().setSigningKey(key).build()

        fun create(subject: String, claims: Map<String, Any> = mapOf(), validTill: LocalDateTime = LocalDateTime.now().plusHours(1)): String =
            Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(Date())
                .setExpiration(Date.from(validTill.atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(key).compact()

        private fun parse(jws: String): Claims = parser.parseClaimsJws(jws).body

        fun validate(token: String, userDetails: MyUserDetails): Boolean =
            with(parse(token)){
                !expired && validUser(this, userDetails)
            }

        fun extractUserName(token: String) = parse(token).subject

        private val Claims.expired: Boolean
            get() = expiration.before(Date())

        private fun validUser(claims: Claims, userDetails: MyUserDetails): Boolean = claims.subject == userDetails.username
    }
}

fun main() {
    println(JwtUtils.create("aa", claims = mapOf("blah" to "bluh")))
}
