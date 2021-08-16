package com.github.bademux.spring_oauth2_resourceserver

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.ConsoleNotifier
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.lang.Void as Should
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig
import static com.github.tomakehurst.wiremock.http.RequestMethod.GET
import static com.github.tomakehurst.wiremock.matching.RequestPatternBuilder.newRequestPattern
import static com.nimbusds.jose.JWSAlgorithm.PS512
import static com.nimbusds.jose.jwk.KeyUse.SIGNATURE
import static com.nimbusds.jose.jwk.gen.RSAKeyGenerator.MIN_KEY_SIZE_BITS
import static groovy.json.JsonOutput.toJson

class AuthTestSpec extends Specification {

    Should "auth correctly"() {
        given:
        def jwt = createJwt(KEY, ['demo-admin'])
        when:
        def resp = client.send(
                HttpRequest.newBuilder().uri("http://localhost:$app.port/api/v1/demo".toURI()).GET().header('Authorization', "Bearer ${jwt}").build(),
                HttpResponse.BodyHandlers.ofString()
        )
        then:
        verifyAll {
            authServer.verify(1, newRequestPattern(GET, urlEqualTo('/jwks')))
            assert authServer.findAllUnmatchedRequests().isEmpty(): 'more interactions with server then expected'
        }
        and:
        assert resp.statusCode() == 200: "Body: ${resp.body()}"
    }

    Should "fail auth on no key"() {
        when:
        def resp = client.send(
                HttpRequest.newBuilder().uri("http://localhost:$app.port/api/v1/demo".toURI()).GET().header('Authorization', "Bearer BADJWT").build(),
                HttpResponse.BodyHandlers.ofString()
        )
        then:
        assert authServer.findAllUnmatchedRequests().isEmpty(): 'more interactions with server then expected'
        and:
        resp.statusCode() == 401
    }

    Should "fail auth on bad key"() {
        given:
        def badKey = new RSAKeyGenerator(MIN_KEY_SIZE_BITS).keyUse(SIGNATURE).algorithm(PS512).generate()
        def jwt = createJwt(badKey, ['demo-admin'])
        when:
        def resp = client.send(
                HttpRequest.newBuilder().uri("http://localhost:$app.port/api/v1/demo".toURI()).GET().header('Authorization', "Bearer ${jwt}").build(),
                HttpResponse.BodyHandlers.ofString()
        )
        then:
        verifyAll {
            authServer.verify(1, newRequestPattern(GET, urlEqualTo('/jwks')))
            assert authServer.findAllUnmatchedRequests().isEmpty(): 'more interactions with server then expected'
        }
        and:
        resp.statusCode() == 401
    }

    Should "fail auth on no role"() {
        given:
        def jwt = createJwt(KEY, [])
        when:
        def resp = client.send(
                HttpRequest.newBuilder().uri("http://localhost:$app.port/api/v1/demo".toURI()).GET().header('Authorization', "Bearer ${jwt}").build(),
                HttpResponse.BodyHandlers.ofString()
        )
        then:
        verifyAll {
            authServer.verify(1, newRequestPattern(GET, urlEqualTo('/jwks')))
            assert authServer.findAllUnmatchedRequests().isEmpty(): 'more interactions with server then expected'
        }
        and:
        resp.statusCode() == 403
    }

    private static String createJwt(RSAKey key, List<String> roles) {
        return new SignedJWT(
                new JWSHeader.Builder(new JWSAlgorithm(key.algorithm.name)).keyID(key.keyID).build(),
                new JWTClaimsSet.Builder().jwtID(UUID.randomUUID() as String).issuer('t-mobile.pl')
                        .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                        .issueTime(Date.from(Instant.now())).notBeforeTime(Date.from(Instant.EPOCH))
                        .subject('voms').audience('voms').claim('clientId', 'voms').claim('type', 'bearer')
                        .claim('resource_access', [account: [roles: ['demo-admin']]])
                        .claim('realm_access', [roles: roles]).claim('scope', ['default'])
                        .build()
        ).with(true, { sign(new RSASSASigner(key)) }).serialize()
    }

    final static HttpClient client = HttpClient.newHttpClient()
    final static RSAKey KEY = new RSAKeyGenerator(MIN_KEY_SIZE_BITS).keyUse(SIGNATURE).algorithm(PS512).generate()

    @Shared
    @AutoCleanup(value = 'stop')
    WireMockServer authServer = new WireMockServer(wireMockConfig().notifier(new ConsoleNotifier(true)).dynamicPort())
            .with(true, { server ->
                server.start()
                server.stubFor(get(urlEqualTo('/jwks')).willReturn(aResponse().withStatus(200).withBody(toJson([keys: [KEY.toJSONObject()]]))))
            })

    @Shared
    @AutoCleanup
    Application app = Application.run("""--spring.application.json=${toJson([
            'spring.security'                                      : true,
            'server.port'                                          : 0, //random
            'spring.security.oauth2.resourceserver.jwt.jwk-set-uri': "${authServer.baseUrl()}/jwks",
    ])}""")

}

